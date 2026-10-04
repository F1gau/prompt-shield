"""
Общие фикстуры.

Приложение хранит config.json и SQLite-базу в «папке данных». Чтобы
тесты никогда не трогали реальные данные и не зависели от порядка
запуска, папка данных подменяется временной (PROMPTSHIELD_DATA_DIR) ДО
первого импорта приложения — пути вычисляются при импорте модулей.
"""

import os
import sys
import tempfile

_DATA_DIR = tempfile.mkdtemp(prefix="promptshield-tests-")
os.environ["PROMPTSHIELD_DATA_DIR"] = _DATA_DIR
os.environ.pop("PROMPTSHIELD_ADMIN_PASSWORD", None)
os.environ.pop("PROMPTSHIELD_LICENSE_SECRET", None)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import pytest  # noqa: E402

from app import create_app  # noqa: E402
from core import auth, ratelimit  # noqa: E402
from core.config import CONFIG_FILE, load_config  # noqa: E402
from core.db import get_conn, init_db  # noqa: E402
from core.users import create_user  # noqa: E402


ADMIN = ("boss", "correct-horse-battery")
ANALYST = ("alice", "analyst-pass-123")


@pytest.fixture(scope="session")
def app():
    application = create_app()
    application.config.update(TESTING=True)
    return application


@pytest.fixture(autouse=True)
def clean_state():
    """Чистое состояние перед каждым тестом: пустые таблицы, дефолтный
    конфиг, сброшены счётчики блокировки входа и rate limit."""

    init_db()

    with get_conn() as conn:
        for table in ("users", "incidents", "audit_log", "feedback", "scan_runs", "scan_seen"):
            conn.execute(f"DELETE FROM {table}")

    if os.path.exists(CONFIG_FILE):
        os.remove(CONFIG_FILE)

    auth._FAILED_ATTEMPTS.clear()
    ratelimit._HITS.clear()

    yield


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def admin_user():
    create_user(ADMIN[0], ADMIN[1], "admin")
    return ADMIN


@pytest.fixture
def analyst_user():
    create_user(ANALYST[0], ANALYST[1], "analyst")
    return ANALYST


@pytest.fixture
def api_key():
    return load_config()["api_key"]


def get_csrf(client, path="/login"):
    """Открывает страницу с формой и возвращает CSRF-токен сессии."""

    client.get(path)

    with client.session_transaction() as sess:
        return sess.get("csrf_token", "")


def login(client, username, password):
    token = get_csrf(client)

    return client.post(
        "/login",
        data={"username": username, "password": password, "csrf_token": token},
    )


@pytest.fixture
def login_as(client):
    def _login(user):
        return login(client, user[0], user[1])
    return _login
