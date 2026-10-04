import io

from core.config import load_config, save_config
from tests.conftest import ADMIN


DEMO_TEXT = (
    "Отправить договор ООО \"Ромашка\"\n"
    "Контактное лицо: Иванов Иван Иванович\n"
    "Телефон: +7 912 345 67 89\n"
    "API key: sk_live_abcdef1234567890abcdef1234567890\n"
    "password = Sup3rS3cret!\n"
)


def post_json(client, path, payload, key=None):
    headers = {"X-API-Key": key} if key else {}
    return client.post(path, json=payload, headers=headers)


# ---------- ключ API ----------

def test_analyze_without_api_key_is_rejected(client):
    response = post_json(client, "/api/analyze", {"text": "hello"})

    assert response.status_code == 401
    assert response.get_json()["error"] == "unauthorized"


def test_analyze_with_wrong_api_key_is_rejected(client, api_key):
    response = post_json(client, "/api/analyze", {"text": "hello"}, key=api_key + "x")
    assert response.status_code == 401


def test_all_api_endpoints_require_key(client):
    for path in ("/api/analyze", "/api/mask", "/api/report", "/api/upload"):
        assert client.post(path, json={"text": "x"}).status_code == 401, path


def test_regenerated_api_key_invalidates_old_one(client, api_key):
    from core.config import regenerate_api_key

    new_key = regenerate_api_key()

    assert post_json(client, "/api/analyze", {"text": "hi"}, key=api_key).status_code == 401
    assert post_json(client, "/api/analyze", {"text": "hi"}, key=new_key).status_code == 200


# ---------- /api/analyze ----------

def test_analyze_returns_findings_and_risk(client, api_key):
    response = post_json(client, "/api/analyze", {"text": DEMO_TEXT}, key=api_key)

    assert response.status_code == 200
    assert response.is_json

    body = response.get_json()
    types = {f["type"] for f in body["findings"]}

    assert {"ФИО", "PHONE", "API_KEY", "ОРГАНИЗАЦИЯ"} <= types
    assert body["risk"] in ("Высокий", "Критический")
    assert body["action"] == "BLOCK"
    assert set(body) >= {"findings", "entities", "risk", "truncated", "action", "action_label", "provider_blocked"}


def test_analyze_clean_text_is_allowed(client, api_key):
    body = post_json(client, "/api/analyze", {"text": "Объясни, что такое рекурсия"}, key=api_key).get_json()

    assert body["findings"] == []
    assert body["risk"] == "Низкий"
    assert body["action"] == "ALLOW"


def test_analyze_empty_body_does_not_crash(client, api_key):
    response = client.post("/api/analyze", data="not json", headers={"X-API-Key": api_key})

    assert response.status_code == 200
    assert response.get_json()["findings"] == []


def test_analyze_blocked_provider(client, api_key):
    cfg = load_config()
    cfg["ai_providers"]["chatgpt"]["allowed"] = False
    save_config(cfg)

    body = post_json(client, "/api/analyze", {"text": "Привет", "destination": "chatgpt"}, key=api_key).get_json()

    assert body["provider_blocked"] is True
    assert body["action"] == "BLOCK"


def test_analyze_saves_incident_without_sensitive_values(client, api_key):
    from core.logger import get_logs

    post_json(client, "/api/analyze", {"text": DEMO_TEXT}, key=api_key)
    logs = get_logs()

    assert len(logs) == 1
    dumped = str(logs)
    assert "sk_live_abcdef" not in dumped
    assert "Иванов" not in dumped
    assert "API_KEY" in logs[0]["types"]


def test_analyze_works_for_logged_in_session(client, admin_user, login_as):
    login_as(ADMIN)
    assert post_json(client, "/api/analyze", {"text": "Привет"}).status_code == 200


# ---------- /api/mask ----------

def test_mask_endpoint(client, api_key):
    response = post_json(client, "/api/mask", {"text": DEMO_TEXT}, key=api_key)
    masked = response.get_json()["masked"]

    assert response.status_code == 200
    assert "sk_live_abcdef" not in masked
    assert "Иванов" not in masked
    assert "[API_KEY]" in masked


# ---------- /api/upload ----------

def test_upload_text_file(client, api_key):
    data = {"file": (io.BytesIO(DEMO_TEXT.encode("utf-8")), "договор.txt")}

    response = client.post("/api/upload", data=data, headers={"X-API-Key": api_key},
                           content_type="multipart/form-data")
    body = response.get_json()

    assert response.status_code == 200
    assert body["filename"] == "договор.txt"
    assert any(f["type"] == "API_KEY" for f in body["findings"])


def test_upload_unsupported_extension(client, api_key):
    data = {"file": (io.BytesIO(b"MZ"), "virus.exe")}

    response = client.post("/api/upload", data=data, headers={"X-API-Key": api_key},
                           content_type="multipart/form-data")

    assert response.status_code == 400


def test_upload_without_file(client, api_key):
    response = client.post("/api/upload", data={}, headers={"X-API-Key": api_key},
                           content_type="multipart/form-data")
    assert response.status_code == 400


def test_upload_with_spoofed_extension_is_not_analysed(client, api_key):
    data = {"file": (io.BytesIO(b"MZ\x90\x00 not really a docx"), "fake.docx")}

    response = client.post("/api/upload", data=data, headers={"X-API-Key": api_key},
                           content_type="multipart/form-data")

    assert "error" in response.get_json()


# ---------- /api/report ----------

def test_report_returns_pdf(client, api_key):
    response = post_json(client, "/api/report", {"text": DEMO_TEXT, "analyst_name": "Тест"}, key=api_key)

    assert response.status_code == 200
    assert response.data.startswith(b"%PDF")


# ---------- прочее ----------

def test_health_endpoint(client):
    assert client.get("/health").get_json() == {"status": "ok", "service": "promptshield"}


def test_unknown_api_path_returns_json_404(client):
    response = client.get("/api/does-not-exist")

    assert response.status_code == 404
    assert response.get_json()["error"] == "not_found"


def test_rate_limit_returns_429(client, api_key):
    codes = [post_json(client, "/api/mask", {"text": "x"}, key=api_key).status_code for _ in range(61)]

    assert codes[:60] == [200] * 60
    assert codes[60] == 429
