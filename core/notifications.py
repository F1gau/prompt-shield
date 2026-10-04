"""
Уведомления о критичных инцидентах и экспорт в SIEM.

Все каналы — best effort: если отправка не удалась (нет сети, неверные
настройки SMTP и т.д.), это только пишется в лог приложения и не
прерывает основной процесс проверки текста/файла.
"""

import json
import logging
import smtplib
import socket
from email.mime.text import MIMEText

try:
    import requests
except ImportError:
    requests = None


logger = logging.getLogger("promptshield.notifications")


# ==================================================
# EMAIL
# ==================================================

def send_email(notif_cfg, subject, body):

    if not notif_cfg.get("email_enabled"):
        return False

    host = notif_cfg.get("smtp_host")
    to_addr = notif_cfg.get("email_to")

    if not host or not to_addr:
        logger.warning("Email-уведомления включены, но не указан SMTP-сервер или адрес получателя")
        return False

    try:
        msg = MIMEText(body, "plain", "utf-8")
        msg["Subject"] = subject
        msg["From"] = notif_cfg.get("email_from") or notif_cfg.get("smtp_user") or "promptshield@localhost"
        msg["To"] = to_addr

        port = notif_cfg.get("smtp_port", 587)

        with smtplib.SMTP(host, port, timeout=10) as server:

            if notif_cfg.get("smtp_use_tls", True):
                server.starttls()

            if notif_cfg.get("smtp_user"):
                server.login(notif_cfg["smtp_user"], notif_cfg.get("smtp_password", ""))

            server.send_message(msg)

        return True

    except Exception as e:
        logger.warning("Не удалось отправить email-уведомление: %s", e)
        return False


# ==================================================
# WEBHOOK (JSON или CEF)
# ==================================================

def format_cef(incident, organization="PromptShield"):
    """
    Common Event Format — распознаётся большинством SIEM
    (ArcSight, QRadar, Splunk и др.) без дополнительной настройки парсера.
    """

    severity_map = {"Низкий": 2, "Средний": 5, "Высокий": 7, "Критический": 10}
    severity = severity_map.get(incident.get("risk"), 3)

    extension = " ".join([
        f"src=localhost",
        f"cs1Label=Source cs1={incident.get('source', '')}",
        f"cs2Label=Types cs2={','.join(incident.get('types', []))}",
        f"cnt={incident.get('findings_count', 0)}",
        f"fname={incident.get('filename') or '-'}",
    ])

    return (
        f"CEF:0|{organization}|PromptShield|1.0|{incident.get('risk', 'unknown')}|"
        f"Sensitive data detected|{severity}|{extension}"
    )


def send_webhook(notif_cfg, incident, organization="PromptShield"):

    if not notif_cfg.get("webhook_enabled"):
        return False

    url = notif_cfg.get("webhook_url")

    if not url:
        logger.warning("Webhook-уведомления включены, но не указан URL")
        return False

    if requests is None:
        logger.warning("Модуль requests не установлен — webhook не отправлен")
        return False

    try:
        fmt = notif_cfg.get("webhook_format", "json")

        if fmt == "cef":
            payload = {"message": format_cef(incident, organization)}
        else:
            payload = incident

        requests.post(url, json=payload, timeout=10)
        return True

    except Exception as e:
        logger.warning("Не удалось отправить webhook-уведомление: %s", e)
        return False


# ==================================================
# SYSLOG (для SIEM без webhook-приёмника)
# ==================================================

def send_syslog(notif_cfg, incident, organization="PromptShield"):

    if not notif_cfg.get("syslog_enabled"):
        return False

    host = notif_cfg.get("syslog_host")
    port = notif_cfg.get("syslog_port", 514)

    if not host:
        logger.warning("Syslog-уведомления включены, но не указан адрес сервера")
        return False

    try:
        message = format_cef(incident, organization)

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(message.encode("utf-8"), (host, port))
        sock.close()

        return True

    except Exception as e:
        logger.warning("Не удалось отправить syslog-уведомление: %s", e)
        return False


# ==================================================
# ГЛАВНАЯ ТОЧКА ВХОДА
# ==================================================

def notify_incident(incident, notif_cfg, organization="PromptShield"):
    """Рассылает уведомление во все включённые каналы, если риск
    инцидента входит в notify_on_risk."""

    risk = incident.get("risk")
    triggers = notif_cfg.get("notify_on_risk", ["Высокий", "Критический"])

    if risk not in triggers:
        return

    subject = f"[Промпт-Щит] Обнаружен инцидент: риск «{risk}»"

    body = (
        f"Уровень риска: {risk}\n"
        f"Источник: {incident.get('source')}\n"
        f"Файл: {incident.get('filename') or '-'}\n"
        f"Типы данных: {', '.join(incident.get('types', []))}\n"
        f"Найдено совпадений: {incident.get('findings_count', 0)}\n"
        f"Время: {incident.get('timestamp')}\n"
    )

    try:
        send_email(notif_cfg, subject, body)
    except Exception:
        logger.exception("Ошибка при отправке email-уведомления")

    try:
        send_webhook(notif_cfg, incident, organization)
    except Exception:
        logger.exception("Ошибка при отправке webhook-уведомления")

    try:
        send_syslog(notif_cfg, incident, organization)
    except Exception:
        logger.exception("Ошибка при отправке syslog-уведомления")
