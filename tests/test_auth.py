import pytest

from core import auth
from core.users import (
    bootstrap_admin_from_env,
    create_user,
    get_user_by_username,
    has_users,
    verify_local_password,
)
from tests.conftest import ADMIN, ANALYST, get_csrf, login


# ---------- первоначальная настройка (без admin/admin) ----------

def test_no_default_admin_is_created(client):
    assert not has_users()
    assert verify_local_password("admin", "admin") is None


def test_login_redirects_to_setup_when_no_users(client):
    response = client.get("/login")
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/setup")


def test_setup_creates_admin_then_closes(client):
    token = get_csrf(client, "/setup")

    response = client.post("/setup", data={
        "username": "root", "password": "long-enough-pass",
        "password_confirm": "long-enough-pass", "csrf_token": token,
    })

    assert response.status_code == 302
    assert has_users()
    assert get_user_by_username("root")["role"] == "admin"

    # после создания админа страница настройки больше недоступна
    assert client.get("/setup").status_code == 302


@pytest.mark.parametrize("password, confirm", [("short", "short"), ("long-enough-pass", "different-pass")])
def test_setup_rejects_bad_password(client, password, confirm):
    token = get_csrf(client, "/setup")

    response = client.post("/setup", data={
        "username": "root", "password": password,
        "password_confirm": confirm, "csrf_token": token,
    })

    assert response.status_code == 200
    assert not has_users()


def test_setup_requires_csrf_token(client):
    client.get("/setup")
    response = client.post("/setup", data={
        "username": "root", "password": "long-enough-pass", "password_confirm": "long-enough-pass",
    })
    assert response.status_code == 400
    assert not has_users()


def test_admin_from_environment(monkeypatch):
    monkeypatch.setenv("PROMPTSHIELD_ADMIN_USER", "envadmin")
    monkeypatch.setenv("PROMPTSHIELD_ADMIN_PASSWORD", "from-env-password")

    assert bootstrap_admin_from_env() is True
    assert verify_local_password("envadmin", "from-env-password")

    # повторный вызов ничего не меняет
    assert bootstrap_admin_from_env() is False


def test_no_admin_from_environment_without_password(monkeypatch):
    monkeypatch.delenv("PROMPTSHIELD_ADMIN_PASSWORD", raising=False)
    assert bootstrap_admin_from_env() is False
    assert not has_users()


# ---------- пароли ----------

def test_password_is_stored_as_hash(admin_user):
    stored = get_user_by_username(ADMIN[0])["password_hash"]
    assert stored != ADMIN[1]
    assert ADMIN[1] not in stored
    assert stored.startswith(("scrypt:", "pbkdf2:"))


# ---------- вход ----------

def test_successful_login(client, admin_user):
    response = login(client, *ADMIN)

    assert response.status_code == 302

    with client.session_transaction() as sess:
        assert sess["logged_in"] is True
        assert sess["username"] == ADMIN[0]
        assert sess["role"] == "admin"


def test_wrong_password(client, admin_user):
    response = login(client, ADMIN[0], "wrong-password")

    assert response.status_code == 200
    assert "Неверное имя пользователя или пароль" in response.get_data(as_text=True)

    with client.session_transaction() as sess:
        assert not sess.get("logged_in")


def test_unknown_user(client, admin_user):
    assert login(client, "nobody", "whatever-password").status_code == 200


def test_inactive_user_cannot_login(client, admin_user):
    from core.users import set_user_active
    set_user_active(ADMIN[0], False)

    assert login(client, *ADMIN).status_code == 200


def test_lockout_after_repeated_failures(client, admin_user):
    for _ in range(auth.MAX_ATTEMPTS):
        login(client, ADMIN[0], "wrong-password")

    # даже верный пароль теперь отклоняется
    response = login(client, *ADMIN)

    assert response.status_code == 200
    assert "Слишком много неудачных попыток" in response.get_data(as_text=True)

    with client.session_transaction() as sess:
        assert not sess.get("logged_in")


def test_successful_login_resets_failed_attempts(client, admin_user):
    for _ in range(auth.MAX_ATTEMPTS - 1):
        login(client, ADMIN[0], "wrong-password")

    assert login(client, *ADMIN).status_code == 302
    assert not auth._FAILED_ATTEMPTS


def test_login_requires_csrf_token(client, admin_user):
    client.get("/login")
    response = client.post("/login", data={"username": ADMIN[0], "password": ADMIN[1]})
    assert response.status_code == 400


@pytest.mark.parametrize("target", ["https://evil.example/", "//evil.example/", "/\\evil.example"])
def test_login_does_not_redirect_to_external_urls(client, admin_user, target):
    token = get_csrf(client)

    response = client.post(f"/login?next={target}", data={
        "username": ADMIN[0], "password": ADMIN[1], "csrf_token": token,
    })

    assert response.status_code == 302
    assert "evil.example" not in response.headers["Location"]


def test_login_redirects_to_internal_next(client, admin_user):
    token = get_csrf(client)

    response = client.post("/login?next=/settings", data={
        "username": ADMIN[0], "password": ADMIN[1], "csrf_token": token,
    })

    assert response.headers["Location"].endswith("/settings")


def test_session_cookie_flags(client, admin_user):
    response = login(client, *ADMIN)
    cookie = response.headers.get("Set-Cookie", "")

    assert "HttpOnly" in cookie
    assert "SameSite=Lax" in cookie


def test_logout(client, admin_user):
    login(client, *ADMIN)
    client.get("/logout")

    with client.session_transaction() as sess:
        assert not sess.get("logged_in")


# ---------- защищённые страницы и роли ----------

@pytest.mark.parametrize("path", ["/", "/check", "/files", "/incidents", "/settings", "/users", "/audit", "/license", "/reports", "/backup", "/scan"])
def test_protected_pages_redirect_anonymous_to_login(client, admin_user, path):
    response = client.get(path)

    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


@pytest.mark.parametrize("path", ["/", "/check", "/files", "/incidents", "/settings"])
def test_analyst_can_open_regular_pages(client, analyst_user, login_as, path):
    login_as(ANALYST)
    assert client.get(path).status_code == 200


@pytest.mark.parametrize("path", ["/users", "/audit", "/license", "/reports", "/backup", "/scan"])
def test_analyst_cannot_open_admin_pages(client, analyst_user, login_as, path):
    login_as(ANALYST)
    assert client.get(path).status_code == 403


@pytest.mark.parametrize("path", ["/users", "/audit", "/license", "/reports", "/backup", "/scan"])
def test_admin_can_open_admin_pages(client, admin_user, login_as, path):
    login_as(ADMIN)
    assert client.get(path).status_code == 200


def test_analyst_cannot_change_policy(client, analyst_user, login_as):
    login_as(ANALYST)
    token = get_csrf(client, "/settings")

    response = client.post("/settings", data={
        "form_type": "api_key", "csrf_token": token,
    })

    assert "Только администратор" in response.get_data(as_text=True)


def test_admin_can_create_user_and_new_user_can_login(client, admin_user, login_as):
    login_as(ADMIN)
    token = get_csrf(client, "/users")

    client.post("/users", data={
        "action": "create", "username": "bob", "password": "bobs-password-1",
        "role": "analyst", "csrf_token": token,
    })

    assert get_user_by_username("bob")["role"] == "analyst"

    other = client.application.test_client()
    assert login(other, "bob", "bobs-password-1").status_code == 302


def test_short_password_rejected_when_creating_user(client, admin_user, login_as):
    login_as(ADMIN)
    token = get_csrf(client, "/users")

    client.post("/users", data={
        "action": "create", "username": "bob", "password": "123",
        "role": "analyst", "csrf_token": token,
    })

    assert get_user_by_username("bob") is None


def test_cannot_delete_own_account(client, admin_user, login_as):
    login_as(ADMIN)
    token = get_csrf(client, "/users")

    client.post("/users", data={"action": "delete", "username": ADMIN[0], "csrf_token": token})

    assert get_user_by_username(ADMIN[0]) is not None


def test_duplicate_username_rejected(admin_user):
    with pytest.raises(ValueError):
        create_user(ADMIN[0], "another-password", "analyst")
