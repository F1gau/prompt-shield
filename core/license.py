"""
Триал и лицензирование.

Важная оговорка: это ОФЛАЙН-лицензирование (без сервера активации).
Ключ подписывается HMAC-SHA256 с секретом, встроенным в код приложения.
Это стандартный уровень защиты для многих десктоп/on-prem продуктов,
но не является криптографически неприступным — технически
подготовленный человек с доступом к исходному коду может
сгенерировать собственный ключ. Полноценная защита потребовала бы
сервера активации с проверкой в реальном времени, что противоречит
принципу «работает полностью локально», на котором построен продукт.
Здесь этот механизм больше играет роль организационного барьера и
способа учёта лицензий, а не защиты от целенаправленного взлома.
"""

import os
import json
import base64
import hashlib
import hmac
from datetime import datetime, timedelta

from core.config import load_config, update_config


# ДЕМО-секрет: он намеренно публичный и НЕ является производственным.
# Любой, кто видит исходники, может подписать им лицензионный ключ — это
# нормально для учебного/демонстрационного режима (триал + проверка ключа
# работают «из коробки»), но не защита от обхода.
#
# Реальный секрет задаётся переменной окружения PROMPTSHIELD_LICENSE_SECRET
# и не хранится в репозитории. Тот же секрет должен быть и у генератора
# ключей (scripts/generate_license.py), и у приложения клиента.
_DEMO_LICENSE_SECRET = b"promptshield-demo-license-secret-NOT-FOR-PRODUCTION"


def _license_secret() -> bytes:

    env_secret = os.environ.get("PROMPTSHIELD_LICENSE_SECRET")

    if env_secret:
        return env_secret.encode("utf-8")

    return _DEMO_LICENSE_SECRET


def is_using_demo_secret() -> bool:
    return not os.environ.get("PROMPTSHIELD_LICENSE_SECRET")


class LicenseLimitError(Exception):
    """Триал закончился (по времени или по числу проверок)."""
    pass


# ==================================================
# ПОДПИСЬ / ПРОВЕРКА КЛЮЧА
# ==================================================

def _b64_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def generate_license_key(payload: dict) -> str:
    """
    Генерация ключа — используется ПРОДАВЦОМ (вами), не встраивается
    в клиентский UI. payload например:
    {"org": "ООО Ромашка", "seats": 50, "expires": "2027-07-01"}
    """

    payload_json = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
    signature = hmac.new(_license_secret(), payload_json, hashlib.sha256).digest()

    return f"{_b64_encode(payload_json)}.{_b64_encode(signature)}"


def validate_license_key(key: str):
    """Возвращает payload (dict) если ключ подлинный и не просрочен, иначе None."""

    try:
        payload_b64, sig_b64 = key.strip().split(".")
        payload_json = _b64_decode(payload_b64)
        signature = _b64_decode(sig_b64)
    except Exception:
        return None

    expected_signature = hmac.new(_license_secret(), payload_json, hashlib.sha256).digest()

    if not hmac.compare_digest(signature, expected_signature):
        return None

    try:
        payload = json.loads(payload_json)
    except Exception:
        return None

    expires = payload.get("expires")

    if expires:
        try:
            if datetime.strptime(expires, "%Y-%m-%d") < datetime.now():
                payload["_expired"] = True
        except ValueError:
            pass

    return payload


# ==================================================
# АКТИВАЦИЯ
# ==================================================

def activate_license(key: str):

    payload = validate_license_key(key)

    if payload is None:
        raise ValueError("Ключ не прошёл проверку подписи — недействителен.")

    if payload.get("_expired"):
        raise ValueError(f"Ключ действителен, но истёк {payload.get('expires')}.")

    cfg = load_config()
    lic = dict(cfg.get("license", {}))

    lic.update({
        "mode": "licensed",
        "license_key": key,
        "license_info": payload
    })

    update_config(license=lic)

    return payload


def deactivate_license():

    cfg = load_config()
    lic = dict(cfg.get("license", {}))

    lic.update({"mode": "trial", "license_key": None, "license_info": None})

    update_config(license=lic)


# ==================================================
# ТРИАЛ: УЧЁТ И ОГРАНИЧЕНИЯ
# ==================================================

def _ensure_trial_started(lic):

    if not lic.get("trial_started_at"):
        lic["trial_started_at"] = datetime.now().isoformat(timespec="seconds")

    return lic


def get_license_status():
    """
    Возвращает состояние лицензии для отображения в интерфейсе и для
    принятия решения «пускать/не пускать» дальнейшие проверки.
    """

    cfg = load_config()
    lic = dict(cfg.get("license", {}))

    if lic.get("mode") == "licensed" and lic.get("license_info"):

        info = lic["license_info"]
        expires = info.get("expires")
        expired = False

        if expires:
            try:
                expired = datetime.strptime(expires, "%Y-%m-%d") < datetime.now()
            except ValueError:
                pass

        return {
            "mode": "licensed",
            "expired": expired,
            "organization": info.get("org"),
            "seats": info.get("seats"),
            "expires": expires,
            "blocked": expired
        }

    lic = _ensure_trial_started(lic)
    update_config(license=lic)

    started = datetime.fromisoformat(lic["trial_started_at"])
    trial_days = lic.get("trial_days", 14)
    days_left = trial_days - (datetime.now() - started).days
    checks_used = lic.get("trial_checks_used", 0)
    checks_max = lic.get("trial_max_checks", 500)

    return {
        "mode": "trial",
        "days_left": max(0, days_left),
        "checks_used": checks_used,
        "checks_max": checks_max,
        "checks_left": max(0, checks_max - checks_used),
        "blocked": days_left <= 0 or checks_used >= checks_max
    }


def register_check():
    """
    Вызывается перед каждой проверкой текста/файла. Увеличивает счётчик
    использованных проверок в триале и блокирует работу при
    исчерпании лимита. В режиме "licensed" (с действующим ключом)
    ограничений нет.
    """

    status = get_license_status()

    if status["mode"] == "licensed":
        if status["blocked"]:
            raise LicenseLimitError(
                f"Срок действия лицензии истёк ({status.get('expires')}). "
                "Обратитесь к поставщику для продления."
            )
        return

    if status["blocked"]:
        if status["days_left"] <= 0:
            raise LicenseLimitError(
                f"Пробный период (14 дней) закончился. "
                "Для продолжения работы активируйте лицензионный ключ в разделе «Лицензия»."
            )
        raise LicenseLimitError(
            f"Достигнут лимит пробного периода ({status['checks_max']} проверок). "
            "Для продолжения работы активируйте лицензионный ключ в разделе «Лицензия»."
        )

    cfg = load_config()
    lic = dict(cfg.get("license", {}))
    lic["trial_checks_used"] = lic.get("trial_checks_used", 0) + 1
    update_config(license=lic)
