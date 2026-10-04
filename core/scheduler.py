"""
Фоновое сканирование папок/сетевых дисков по расписанию.

Работает в отдельном демоне-потоке внутри процесса Flask — без
дополнительных внешних сервисов или cron. Настройки (папка, интервал,
включено/выключено) читаются из config.json перед каждым циклом, так
что изменения в /settings применяются без перезапуска приложения
(в течение одной минуты).
"""

import os
import time
import uuid
import logging
import threading
from datetime import datetime

from core.config import load_config
from core.db import get_conn, init_db
from core.file_extractor import extract_text_with_meta, SUPPORTED_EXTENSIONS
from core.analyzer import analyze_text
from core.logger import save_incident


logger = logging.getLogger("promptshield.scheduler")

_STARTED = False
_LOCK = threading.Lock()
_LAST_STATUS = {"running": False, "last_run": None}


# ==================================================
# СКАНИРОВАНИЕ ОДНОЙ ПАПКИ
# ==================================================

def _already_seen(conn, filepath, mtime, size):

    row = conn.execute(
        "SELECT mtime, size FROM scan_seen WHERE filepath = ?",
        (filepath,)
    ).fetchone()

    if not row:
        return False

    return row["mtime"] == mtime and row["size"] == size


def _mark_seen(conn, filepath, mtime, size):

    conn.execute(
        """
        INSERT INTO scan_seen (filepath, mtime, size, last_scanned_at)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(filepath) DO UPDATE SET
            mtime = excluded.mtime,
            size = excluded.size,
            last_scanned_at = excluded.last_scanned_at
        """,
        (filepath, mtime, size, datetime.now().isoformat(timespec="seconds"))
    )


def scan_folder_once(folder, extensions, settings=None):
    """
    Однократный проход по папке. Возвращает статистику
    {"files_scanned": N, "files_flagged": N, "error": None|str}.
    """

    init_db()

    if settings is None:
        settings = load_config()

    stats = {"files_scanned": 0, "files_flagged": 0, "error": None}

    if not folder or not os.path.isdir(folder):
        stats["error"] = f"Папка не найдена или недоступна: {folder}"
        return stats

    extensions = set(e.lower() for e in (extensions or SUPPORTED_EXTENSIONS))

    run_id = str(uuid.uuid4())
    started_at = datetime.now().isoformat(timespec="seconds")

    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO scan_runs (id, started_at, folder, status)
            VALUES (?, ?, ?, 'running')
            """,
            (run_id, started_at, folder)
        )

    try:

        for root, _dirs, files in os.walk(folder):

            for fname in files:

                ext = os.path.splitext(fname)[1].lower()

                if ext not in extensions:
                    continue

                full_path = os.path.join(root, fname)

                try:
                    st = os.stat(full_path)
                except OSError:
                    continue

                with get_conn() as conn:
                    seen = _already_seen(conn, full_path, st.st_mtime, st.st_size)

                if seen:
                    continue

                stats["files_scanned"] += 1

                try:
                    meta = extract_text_with_meta(full_path, ext=ext)
                    text = meta.get("text", "")

                    if text and text.strip():

                        result = analyze_text(text, settings)

                        if result.get("findings"):

                            save_incident(
                                result.get("findings", []),
                                result.get("risk", "Низкий"),
                                source="scan",
                                filename=full_path
                            )

                            stats["files_flagged"] += 1

                except Exception as e:
                    logger.warning("Ошибка при сканировании файла %s: %s", full_path, e)

                with get_conn() as conn:
                    _mark_seen(conn, full_path, st.st_mtime, st.st_size)

        with get_conn() as conn:
            conn.execute(
                """
                UPDATE scan_runs
                SET finished_at = ?, files_scanned = ?, files_flagged = ?, status = 'completed'
                WHERE id = ?
                """,
                (datetime.now().isoformat(timespec="seconds"), stats["files_scanned"], stats["files_flagged"], run_id)
            )

    except Exception as e:

        stats["error"] = str(e)
        logger.exception("Ошибка фонового сканирования папки %s", folder)

        with get_conn() as conn:
            conn.execute(
                """
                UPDATE scan_runs
                SET finished_at = ?, status = 'error', error = ?
                WHERE id = ?
                """,
                (datetime.now().isoformat(timespec="seconds"), str(e), run_id)
            )

    return stats


# ==================================================
# ФОНОВЫЙ ЦИКЛ
# ==================================================

def _scheduler_loop():

    while True:

        try:
            cfg = load_config()
            scan_cfg = cfg.get("scan", {})

            if scan_cfg.get("enabled") and scan_cfg.get("folder"):

                with _LOCK:
                    _LAST_STATUS["running"] = True

                scan_folder_once(scan_cfg["folder"], scan_cfg.get("extensions"), cfg)

                with _LOCK:
                    _LAST_STATUS["running"] = False
                    _LAST_STATUS["last_run"] = datetime.now().isoformat(timespec="seconds")

            interval = max(5, int(scan_cfg.get("interval_minutes", 60))) * 60

        except Exception:
            logger.exception("Ошибка в цикле фонового сканирования")
            interval = 300

        # проверяем настройки не реже раза в минуту, чтобы изменения
        # в /settings подхватывались быстро, даже если основной
        # интервал сканирования большой
        time.sleep(min(60, interval))


def start_scheduler():
    """Запускает фоновый поток сканирования один раз за жизнь процесса."""

    global _STARTED

    with _LOCK:
        if _STARTED:
            return
        _STARTED = True

    thread = threading.Thread(target=_scheduler_loop, name="promptshield-scheduler", daemon=True)
    thread.start()

    logger.info("Фоновый сканер папок запущен")


def get_scan_status():

    init_db()

    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM scan_runs ORDER BY started_at DESC LIMIT 10"
        ).fetchall()

    runs = [dict(r) for r in rows]

    with _LOCK:
        live = dict(_LAST_STATUS)

    return {"runs": runs, "live": live}


def run_scan_now():
    """Запускает сканирование немедленно, в фоновом потоке (не блокируя запрос)."""

    cfg = load_config()
    scan_cfg = cfg.get("scan", {})

    if not scan_cfg.get("folder"):
        return False, "Папка для сканирования не настроена"

    def _run():
        with _LOCK:
            _LAST_STATUS["running"] = True
        scan_folder_once(scan_cfg["folder"], scan_cfg.get("extensions"), cfg)
        with _LOCK:
            _LAST_STATUS["running"] = False
            _LAST_STATUS["last_run"] = datetime.now().isoformat(timespec="seconds")

    threading.Thread(target=_run, daemon=True).start()

    return True, "Сканирование запущено в фоне"
