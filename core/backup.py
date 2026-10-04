"""
Резервное копирование и восстановление.

Бэкап — это ZIP-файл с двумя вещами: config.json (настройки, политика,
API-ключ) и logs/promptshield.db (журнал инцидентов, пользователи,
аудит). Файл создаётся локально на диске и отдаётся пользователю через
браузер как обычная закачка — никуда по сети не отправляется, если
только пользователь сам не решит переслать его куда-то дальше.

ВАЖНО про содержимое бэкапа: сама база инцидентов, как и раньше, не
содержит значений найденных сущностей (паспортов, токенов и т.д.) —
только метаданные. Поэтому бэкап не более чувствителен, чем обычный
журнал инцидентов внутри приложения. Но он содержит хэши паролей
пользователей и API-ключ — поэтому файл бэкапа сам по себе должен
храниться так же аккуратно, как сам config.json (не отправлять кому
попало, не класть в публичное облако).
"""

import os
import shutil
import zipfile
import tempfile
import logging
from datetime import datetime

from core.paths import data_path, get_data_dir
from core.db import DB_PATH, get_conn
from core.config import CONFIG_FILE


logger = logging.getLogger("promptshield.backup")

BACKUP_MANIFEST_NAME = "promptshield_backup.json"
BACKUP_FORMAT_VERSION = 1


def create_backup():
    """
    Создаёт ZIP-архив с config.json и SQLite-базой в reports/ (та же
    папка, куда уже складываются PDF/XLSX-отчёты — она предназначена
    именно для файлов, которые пользователь скачивает и уносит с
    собой). Возвращает путь к созданному файлу.
    """

    import json

    # WAL-режим SQLite может держать часть данных в файлах -wal/-shm,
    # которые ещё не влиты в основной .db. checkpoint принудительно
    # сбрасывает их в основной файл перед копированием, иначе бэкап
    # рискует оказаться неполным.
    try:
        with get_conn() as conn:
            conn.execute("PRAGMA wal_checkpoint(FULL);")
    except Exception:
        logger.exception("Не удалось выполнить checkpoint базы перед бэкапом")

    filename = datetime.now().strftime("PromptShield_Backup_%Y%m%d_%H%M%S.zip")
    filepath = data_path("reports", filename)

    manifest = {
        "format_version": BACKUP_FORMAT_VERSION,
        "created_at": datetime.now().isoformat(timespec="seconds"),
    }

    with zipfile.ZipFile(filepath, "w", zipfile.ZIP_DEFLATED) as zf:

        if os.path.exists(CONFIG_FILE):
            zf.write(CONFIG_FILE, "config.json")

        if os.path.exists(DB_PATH):
            zf.write(DB_PATH, "promptshield.db")

        zf.writestr(BACKUP_MANIFEST_NAME, json.dumps(manifest, ensure_ascii=False, indent=2))

    return filepath


def validate_backup_file(upload_path):
    """Проверка перед восстановлением: это действительно наш бэкап,
    а не случайный/повреждённый/чужой файл."""

    import json

    try:
        with zipfile.ZipFile(upload_path, "r") as zf:

            names = zf.namelist()

            if BACKUP_MANIFEST_NAME not in names:
                return False, "Файл не похож на бэкап «Промпт-Щита» (отсутствует манифест)."

            if "config.json" not in names and "promptshield.db" not in names:
                return False, "В архиве нет ни config.json, ни базы данных — восстанавливать нечего."

            manifest = json.loads(zf.read(BACKUP_MANIFEST_NAME).decode("utf-8"))

            if manifest.get("format_version", 0) > BACKUP_FORMAT_VERSION:
                return False, "Бэкап создан более новой версией приложения — обновите «Промпт-Щит» перед восстановлением."

            bad = zf.testzip()
            if bad is not None:
                return False, f"Архив повреждён (файл {bad} не читается)."

    except zipfile.BadZipFile:
        return False, "Файл повреждён или не является ZIP-архивом."
    except Exception as e:
        return False, f"Не удалось прочитать файл бэкапа: {e}"

    return True, None


def restore_backup(upload_path):
    """
    Восстанавливает config.json и базу данных из архива, СНАЧАЛА
    сохранив копию текущего состояния (safety-net на случай, если
    восстановленный файл окажется неподходящим — можно откатиться
    вручную из reports/).
    """

    ok, reason = validate_backup_file(upload_path)

    if not ok:
        raise ValueError(reason)

    # предохранитель: бэкапим текущее состояние перед перезаписью
    pre_restore_backup = None
    try:
        pre_restore_backup = create_backup()
    except Exception:
        logger.exception("Не удалось создать предохранительную копию перед восстановлением")

    with zipfile.ZipFile(upload_path, "r") as zf:

        names = zf.namelist()

        if "config.json" in names:
            with zf.open("config.json") as src, open(CONFIG_FILE, "wb") as dst:
                shutil.copyfileobj(src, dst)

        if "promptshield.db" in names:

            # закрываем возможные -wal/-shm файлы старой базы, чтобы
            # не оставить противоречивое состояние после подмены
            for suffix in ("-wal", "-shm"):
                stale = DB_PATH + suffix
                if os.path.exists(stale):
                    try:
                        os.remove(stale)
                    except OSError:
                        pass

            with zf.open("promptshield.db") as src, open(DB_PATH, "wb") as dst:
                shutil.copyfileobj(src, dst)

    return pre_restore_backup


def list_backups():
    """Список ранее созданных бэкапов в reports/ (для отображения в интерфейсе)."""

    reports_dir = data_path("reports", "_placeholder")
    reports_dir = os.path.dirname(reports_dir)

    if not os.path.isdir(reports_dir):
        return []

    result = []

    for name in os.listdir(reports_dir):

        if not name.startswith("PromptShield_Backup_") or not name.endswith(".zip"):
            continue

        full = os.path.join(reports_dir, name)

        try:
            stat = os.stat(full)
        except OSError:
            continue

        result.append({
            "name": name,
            "size_kb": round(stat.st_size / 1024, 1),
            "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(timespec="seconds")
        })

    result.sort(key=lambda x: x["modified"], reverse=True)

    return result
