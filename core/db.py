import os
import sqlite3
import json
import threading
from contextlib import contextmanager


from core.paths import data_path

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = data_path("logs", "promptshield.db")

_LOCK = threading.Lock()


def _connect():

    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

    conn = sqlite3.connect(DB_PATH, timeout=10, check_same_thread=False)
    conn.row_factory = sqlite3.Row

    # WAL значительно улучшает конкурентную работу (несколько
    # одновременных читателей + писатель не блокируют друг друга) —
    # важно при реальной многопользовательской нагрузке в компании.
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")

    return conn


@contextmanager
def get_conn():

    with _LOCK:
        conn = _connect()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()


def init_db():

    with get_conn() as conn:

        conn.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                risk TEXT NOT NULL,
                total REAL NOT NULL DEFAULT 0,
                findings_count INTEGER NOT NULL DEFAULT 0,
                types TEXT NOT NULL DEFAULT '[]',
                source TEXT NOT NULL DEFAULT 'text',
                filename TEXT
            )
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_incidents_timestamp
            ON incidents (timestamp)
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_incidents_risk
            ON incidents (risk)
        """)

        # --------------------------------------------
        # МИГРАЦИЯ: колонка created_by (для фильтрации истории
        # по пользователю — роль "analyst" видит только свои проверки)
        # --------------------------------------------

        existing_cols = {row["name"] for row in conn.execute("PRAGMA table_info(incidents)").fetchall()}

        if "created_by" not in existing_cols:
            conn.execute("ALTER TABLE incidents ADD COLUMN created_by TEXT")

        # --------------------------------------------
        # МИГРАЦИЯ: destination (самодекларируемый AI-сервис) и
        # action (рекомендованное решение ALLOW/MASK/BLOCK)
        # --------------------------------------------

        if "destination" not in existing_cols:
            conn.execute("ALTER TABLE incidents ADD COLUMN destination TEXT")

        if "action" not in existing_cols:
            conn.execute("ALTER TABLE incidents ADD COLUMN action TEXT")

        # --------------------------------------------
        # ПОЛЬЗОВАТЕЛИ И РОЛИ
        # --------------------------------------------

        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT,
                role TEXT NOT NULL DEFAULT 'analyst',
                auth_source TEXT NOT NULL DEFAULT 'local',
                active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                last_login TEXT
            )
        """)

        # --------------------------------------------
        # АУДИТ ДЕЙСТВИЙ (кто/когда/что изменил)
        # --------------------------------------------

        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                username TEXT,
                action TEXT NOT NULL,
                details TEXT
            )
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_audit_timestamp
            ON audit_log (timestamp)
        """)

        # --------------------------------------------
        # ФОНОВОЕ СКАНИРОВАНИЕ ПАПОК
        # --------------------------------------------

        conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_runs (
                id TEXT PRIMARY KEY,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                folder TEXT NOT NULL,
                files_scanned INTEGER NOT NULL DEFAULT 0,
                files_flagged INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'running',
                error TEXT
            )
        """)

        # --------------------------------------------
        # СОСТОЯНИЕ ФОНОВОГО СКАНЕРА: какие файлы уже проверены
        # (по пути + времени изменения), чтобы не создавать новый
        # инцидент на каждый цикл сканирования для неизменившихся файлов
        # --------------------------------------------

        conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_seen (
                filepath TEXT PRIMARY KEY,
                mtime REAL NOT NULL,
                size INTEGER NOT NULL,
                last_scanned_at TEXT NOT NULL
            )
        """)

        # --------------------------------------------
        # ОБРАТНАЯ СВЯЗЬ ПО ЛОЖНЫМ СРАБАТЫВАНИЯМ
        #
        # В отличие от журнала инцидентов, здесь ХРАНИТСЯ само значение
        # найденной сущности — это необходимо, чтобы при повторной
        # проверке можно было узнать "это уже помечали как ложное" и
        # не показывать снова. Пользователь сам инициирует сохранение
        # конкретного значения нажатием кнопки "не утечка" — это
        # осознанный компромисс между приватностью журнала и пользой
        # от обучаемого фильтра, а не тихое протоколирование.
        # --------------------------------------------

        conn.execute("""
            CREATE TABLE IF NOT EXISTS feedback (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                username TEXT,
                type TEXT NOT NULL,
                value TEXT NOT NULL,
                value_lower TEXT NOT NULL
            )
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_feedback_lookup
            ON feedback (type, value_lower)
        """)


def row_to_dict(row):

    d = dict(row)
    d["types"] = json.loads(d.get("types") or "[]")

    return d
