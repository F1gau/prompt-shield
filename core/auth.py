import time
import secrets
from functools import wraps

from flask import session, redirect, url_for, request, jsonify, abort
from werkzeug.security import check_password_hash

from core.config import load_config
from core.users import verify_local_password, touch_last_login
from core.ldap_auth import ldap_authenticate, ldap_user_role


# ==================================================
# BRUTE-FORCE PROTECTION (простая защита от подбора)
# ==================================================

_FAILED_ATTEMPTS = {}

MAX_ATTEMPTS = 5
LOCKOUT_SECONDS = 60


def _client_key():
    return request.remote_addr or "unknown"


def is_locked_out():

    key = _client_key()
    record = _FAILED_ATTEMPTS.get(key)

    if not record:
        return False

    count, last_ts = record

    if count < MAX_ATTEMPTS:
        return False

    if time.time() - last_ts > LOCKOUT_SECONDS:
        _FAILED_ATTEMPTS.pop(key, None)
        return False

    return True


def register_failed_attempt():

    key = _client_key()
    count, _ = _FAILED_ATTEMPTS.get(key, (0, 0))
    _FAILED_ATTEMPTS[key] = (count + 1, time.time())


def reset_attempts():
    _FAILED_ATTEMPTS.pop(_client_key(), None)


# ==================================================
# LOGIN CHECK (локальные пользователи + опционально LDAP/AD)
# ==================================================

def check_login(username, password):
    """
    Возвращает (True, role) при успехе, иначе (False, None).

    Если в настройках включён LDAP — пробуем bind к AD-серверу первым;
    при недоступности LDAP (библиотека не установлена / сервер не
    отвечает) прозрачно откатываемся на локальную базу пользователей,
    чтобы неверная настройка LDAP не заблокировала вход администратору.
    """

    cfg = load_config()
    ldap_cfg = cfg.get("ldap", {})

    if ldap_cfg.get("enabled"):

        ldap_result = ldap_authenticate(username, password, ldap_cfg)

        if ldap_result is True:
            role = ldap_user_role(username, password, ldap_cfg, ldap_cfg.get("admin_group_dn"))
            return True, role

        if ldap_result is False:
            # LDAP явно ответил "неверный пароль" — не пробуем локальную БД,
            # иначе получится, что LDAP-пароль сотрудника подходит и к
            # локальному аккаунту с тем же именем (путаница учётных записей)
            return False, None

        # ldap_result is None -> LDAP недоступен/не настроен, пробуем локально

    user = verify_local_password(username, password)

    if user:
        touch_last_login(username)
        return True, user["role"]

    return False, None


# ==================================================
# DECORATORS
# ==================================================

def login_required(view):

    @wraps(view)
    def wrapped(*args, **kwargs):

        if not session.get("logged_in"):
            return redirect(url_for("routes.login", next=request.path))

        return view(*args, **kwargs)

    return wrapped


def role_required(role):
    """
    Ограничивает доступ по роли. role='admin' — только администраторы
    (управление пользователями, настройками, лицензией). Аналитик
    (role='analyst') может проверять текст/файлы, но не менять
    конфигурацию системы.
    """

    def decorator(view):

        @wraps(view)
        def wrapped(*args, **kwargs):

            if not session.get("logged_in"):
                return redirect(url_for("routes.login", next=request.path))

            if session.get("role") != role and session.get("role") != "admin":
                abort(403, description="Недостаточно прав для этого действия. Обратитесь к администратору.")

            return view(*args, **kwargs)

        return wrapped

    return decorator


def api_key_required(view):
    """
    Защита для внешнего REST API (интеграция с корпоративными
    системами). Ключ передаётся в заголовке X-API-Key, либо
    пользователь может пользоваться API уже будучи залогинен
    в веб-интерфейсе.
    """

    @wraps(view)
    def wrapped(*args, **kwargs):

        if session.get("logged_in"):
            return view(*args, **kwargs)

        cfg = load_config()
        provided = request.headers.get("X-API-Key", "")

        if provided and secrets.compare_digest(provided, cfg.get("api_key", "")):
            return view(*args, **kwargs)

        return jsonify({"error": "unauthorized", "detail": "Требуется X-API-Key либо активная сессия"}), 401

    return wrapped


# ==================================================
# CSRF-ЗАЩИТА ДЛЯ HTML-ФОРМ
#
# Формы в /settings меняют пароль администратора, API-ключ и
# очищают журнал — это чувствительные операции, которые должны
# быть защищены от межсайтовой подделки запроса (CSRF) отдельно
# от политики cookie (SameSite сам по себе не всегда достаточен,
# особенно если приложение когда-либо окажется не на localhost).
# ==================================================

def csrf_token():

    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(16)

    return session["csrf_token"]


def csrf_required(view):

    @wraps(view)
    def wrapped(*args, **kwargs):

        if request.method == "POST":

            sent = request.form.get("csrf_token", "")
            expected = session.get("csrf_token", "")

            if not expected or not secrets.compare_digest(sent, expected):
                abort(400, description="Недействительный CSRF-токен. Обновите страницу и повторите попытку.")

        return view(*args, **kwargs)

    return wrapped
