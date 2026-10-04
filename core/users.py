import os
import uuid
from datetime import datetime

from werkzeug.security import generate_password_hash, check_password_hash

from core.db import get_conn, init_db


ROLES = ("admin", "analyst")


# ==================================================
# BOOTSTRAP: гарантируем, что есть хотя бы один admin
# ==================================================

MIN_PASSWORD_LENGTH = 8


def validate_password(password):
    """Возвращает текст ошибки, если пароль не подходит, иначе None."""

    if len(password or "") < MIN_PASSWORD_LENGTH:
        return f"Пароль слишком короткий (минимум {MIN_PASSWORD_LENGTH} символов)."

    return None


def has_users():

    init_db()

    with get_conn() as conn:
        return conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] > 0


def create_first_admin(username, password):
    """
    Создаёт первого администратора, только если в системе ещё нет
    ни одного пользователя. Возвращает True, если учётная запись
    создана. Проверка и вставка выполняются в одной транзакции, так что
    два одновременных запроса не создадут двух администраторов.
    """

    init_db()

    error = validate_password(password)

    if error:
        raise ValueError(error)

    username = (username or "").strip()

    if not username:
        raise ValueError("Укажите имя администратора.")

    with get_conn() as conn:

        count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]

        if count > 0:
            return False

        conn.execute(
            """
            INSERT INTO users (id, username, password_hash, role, auth_source, active, created_at)
            VALUES (?, ?, ?, 'admin', 'local', 1, ?)
            """,
            (str(uuid.uuid4()), username, generate_password_hash(password), datetime.now().isoformat(timespec="seconds"))
        )

    return True


def bootstrap_admin_from_env():
    """
    Необязательный способ первоначальной настройки без веб-формы
    (удобно для Docker/CI): если пользователей ещё нет и заданы
    переменные PROMPTSHIELD_ADMIN_USER (по умолчанию «admin») и
    PROMPTSHIELD_ADMIN_PASSWORD, администратор создаётся из них.

    Если пароль не задан — ничего не создаётся: при первом входе в
    браузере приложение предложит задать пароль на странице /setup.
    Пароль по умолчанию в коде отсутствует намеренно.
    """

    password = os.environ.get("PROMPTSHIELD_ADMIN_PASSWORD")

    if not password or has_users():
        return False

    username = os.environ.get("PROMPTSHIELD_ADMIN_USER", "admin")

    return create_first_admin(username, password)


# ==================================================
# CRUD
# ==================================================

def list_users():

    init_db()

    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM users ORDER BY created_at ASC").fetchall()

    users = []

    for r in rows:
        d = dict(r)
        d.pop("password_hash", None)
        users.append(d)

    return users


def get_user_by_username(username):

    init_db()

    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        ).fetchone()

    return dict(row) if row else None


def create_user(username, password, role="analyst"):

    init_db()

    if role not in ROLES:
        role = "analyst"

    with get_conn() as conn:

        existing = conn.execute(
            "SELECT id FROM users WHERE username = ?",
            (username,)
        ).fetchone()

        if existing:
            raise ValueError("Пользователь с таким именем уже существует")

        conn.execute(
            """
            INSERT INTO users (id, username, password_hash, role, auth_source, active, created_at)
            VALUES (?, ?, ?, ?, 'local', 1, ?)
            """,
            (
                str(uuid.uuid4()),
                username,
                generate_password_hash(password),
                role,
                datetime.now().isoformat(timespec="seconds")
            )
        )


def set_user_password(username, password):

    init_db()

    with get_conn() as conn:
        conn.execute(
            "UPDATE users SET password_hash = ? WHERE username = ?",
            (generate_password_hash(password), username)
        )


def set_user_role(username, role):

    if role not in ROLES:
        raise ValueError("Недопустимая роль")

    init_db()

    with get_conn() as conn:
        conn.execute(
            "UPDATE users SET role = ? WHERE username = ?",
            (role, username)
        )


def set_user_active(username, active):

    init_db()

    with get_conn() as conn:
        conn.execute(
            "UPDATE users SET active = ? WHERE username = ?",
            (1 if active else 0, username)
        )


def delete_user(username):

    init_db()

    with get_conn() as conn:
        conn.execute("DELETE FROM users WHERE username = ?", (username,))


def touch_last_login(username):

    init_db()

    with get_conn() as conn:
        conn.execute(
            "UPDATE users SET last_login = ? WHERE username = ?",
            (datetime.now().isoformat(timespec="seconds"), username)
        )


# ==================================================
# АУТЕНТИФИКАЦИЯ (локальная)
# ==================================================

def verify_local_password(username, password):

    user = get_user_by_username(username)

    if not user or not user.get("active"):
        return None

    if user.get("auth_source") != "local":
        return None

    if not user.get("password_hash"):
        return None

    if check_password_hash(user["password_hash"], password):
        return user

    return None


def count_admins():

    init_db()

    with get_conn() as conn:
        row = conn.execute(
            "SELECT COUNT(*) FROM users WHERE role = 'admin' AND active = 1"
        ).fetchone()

    return row[0]
