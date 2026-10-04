import os
import json
import secrets
import threading


from core.paths import data_path

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_FILE = data_path("config.json")

_LOCK = threading.Lock()


# ==================================================
# DEFAULTS
# ==================================================

DEFAULT_CONFIG = {
    "organization_name": "Моя компания",

    # ВАЖНО: пароли пользователей теперь хранятся в таблице `users`
    # (core/users.py), а не здесь — это позволяет иметь несколько
    # учётных записей с разными ролями (admin/analyst).
    "secret_key": secrets.token_hex(32),
    "api_key": secrets.token_hex(24),

    "min_confidence": 0.5,

    "detectors": {
        "personal": True,
        "company": True,
        "bank": True,
        "secrets": True,
        "address": True,
        "prompt_injection": True
    },

    "max_text_length": 200000,
    "max_upload_mb": 15,

    # --------------------------------------------
    # WHITELIST — исключения, которые организация не считает утечкой
    # (например, собственный корпоративный домен, тестовые данные)
    # --------------------------------------------
    "whitelist_values": [],
    "whitelist_domains": [],

    # --------------------------------------------
    # LDAP / ACTIVE DIRECTORY (опционально)
    # --------------------------------------------
    "ldap": {
        "enabled": False,
        "server": "",
        "user_dn_template": "{username}",
        "base_dn": "",
        "use_ssl": False,
        "admin_group_dn": ""
    },

    # --------------------------------------------
    # ФОНОВОЕ СКАНИРОВАНИЕ ПАПОК
    # --------------------------------------------
    "scan": {
        "enabled": False,
        "folder": "",
        "interval_minutes": 60,
        "extensions": [".txt", ".pdf", ".docx", ".csv", ".xlsx", ".pptx", ".log", ".json"]
    },

    # --------------------------------------------
    # УВЕДОМЛЕНИЯ (email / webhook / syslog) о критичных инцидентах
    # --------------------------------------------
    "notifications": {
        "notify_on_risk": ["Высокий", "Критический"],

        "email_enabled": False,
        "smtp_host": "",
        "smtp_port": 587,
        "smtp_user": "",
        "smtp_password": "",
        "smtp_use_tls": True,
        "email_from": "",
        "email_to": "",

        "webhook_enabled": False,
        "webhook_url": "",
        "webhook_format": "json",

        "syslog_enabled": False,
        "syslog_host": "",
        "syslog_port": 514
    },

    # --------------------------------------------
    # ПОЛИТИКА AI-СЕРВИСОВ
    #
    # ВАЖНО: это НЕ технический перехват трафика — «Промпт-Щит»
    # не является прокси между сотрудником и AI-сервисом. Пользователь
    # сам указывает на странице проверки, куда планирует отправить
    # текст, а это правило определяет, разрешён ли выбранный сервис.
    # Это организационная мера (аналог политики "разрешено/запрещено"
    # в регламенте), а не техническое ограничение — обойти её,
    # просто не указав сервис или указав неверно, ничего не мешает.
    # --------------------------------------------
    "ai_providers": {
        "chatgpt": {"label": "ChatGPT / OpenAI", "allowed": True},
        "gigachat": {"label": "GigaChat", "allowed": True},
        "yandexgpt": {"label": "YandexGPT", "allowed": True},
        "claude": {"label": "Claude / Anthropic", "allowed": True},
        "local_llm": {"label": "Локальная LLM", "allowed": True},
        "other": {"label": "Другое", "allowed": True}
    },

    # --------------------------------------------
    # ЛИЦЕНЗИЯ / ТРИАЛ
    # --------------------------------------------
    "license": {
        "mode": "trial",
        "trial_started_at": None,
        "trial_days": 14,
        "trial_max_checks": 500,
        "trial_checks_used": 0,
        "license_key": None,
        "license_info": None
    }
}


# ==================================================
# LOAD / SAVE
# ==================================================

def _write(cfg):

    tmp_path = CONFIG_FILE + ".tmp"

    with _LOCK:
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(cfg, f, ensure_ascii=False, indent=4)
            f.flush()
            os.fsync(f.fileno())

        # os.replace — атомарная операция на POSIX и Windows, в отличие
        # от прямой записи в целевой файл: параллельный читатель либо
        # увидит старую, либо новую версию, но никогда — «половину» файла.
        os.replace(tmp_path, CONFIG_FILE)


def _deep_fill_defaults(cfg, defaults):
    """Рекурсивно дозаполняет отсутствующие ключи значениями по
    умолчанию — защита от старого/битого config.json после обновления
    приложения новыми функциями."""

    changed = False

    for key, value in defaults.items():

        if key not in cfg:
            cfg[key] = value
            changed = True
            continue

        if isinstance(value, dict) and isinstance(cfg.get(key), dict):
            if _deep_fill_defaults(cfg[key], value):
                changed = True

    return changed


def load_config():

    if not os.path.exists(CONFIG_FILE):
        _write(DEFAULT_CONFIG)
        return json.loads(json.dumps(DEFAULT_CONFIG))

    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            cfg = json.load(f)
    except Exception:
        cfg = {}

    if _deep_fill_defaults(cfg, DEFAULT_CONFIG):
        _write(cfg)

    return cfg


def save_config(cfg):
    _write(cfg)
    return cfg


def update_config(**kwargs):

    cfg = load_config()

    for key, value in kwargs.items():
        cfg[key] = value

    save_config(cfg)

    return cfg


def regenerate_api_key():

    cfg = load_config()
    cfg["api_key"] = secrets.token_hex(24)
    save_config(cfg)

    return cfg["api_key"]
