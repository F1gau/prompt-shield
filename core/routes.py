import os
import re
import tempfile

from flask import (
    Blueprint,
    render_template,
    request,
    jsonify,
    send_file,
    session,
    redirect,
    url_for,
    current_app
)

from core.analyzer import analyze_text
from core.masker import mask_text
from core.file_extractor import (
    extract_text_with_meta,
    validate_file_signature,
    SUPPORTED_EXTENSIONS
)
from core.logger import save_incident, get_logs, get_stats, clear_logs, get_user_activity
from core.config import load_config, update_config, regenerate_api_key
from core.auth import (
    login_required,
    role_required,
    api_key_required,
    check_login,
    is_locked_out,
    register_failed_attempt,
    reset_attempts,
    csrf_token,
    csrf_required
)
from core.users import (
    list_users,
    create_user,
    set_user_password,
    set_user_role,
    set_user_active,
    delete_user,
    count_admins,
    has_users,
    create_first_admin,
    validate_password,
    ROLES as USER_ROLES
)
from core.audit import log_action, get_audit_log
from core.license import get_license_status, activate_license, register_check, LicenseLimitError
from core.scheduler import get_scan_status, run_scan_now, start_scheduler
from core import ldap_auth

from core.ratelimit import rate_limit
from core.decision import recommend_action, is_provider_blocked, action_label
from core.xlsx_export import export_incidents_xlsx, export_summary_xlsx
from core.paths import data_path
from core.feedback import mark_false_positive, list_feedback, remove_feedback, count_feedback
from core.backup import create_backup, restore_backup, list_backups, validate_backup_file

from pdf.pdf_report import generate_report, generate_summary_report


routes = Blueprint("routes", __name__)


ALLOWED_EXTENSIONS = SUPPORTED_EXTENSIONS

_UNSAFE_NAME_CHARS = re.compile(r'[\\/\x00-\x1f<>:"|?*]')


def safe_display_filename(name):
    """
    Имя файла для отображения/логирования. В отличие от
    werkzeug.secure_filename(), сохраняет кириллицу и другие
    Unicode-символы — только убирает разделители пути и служебные
    символы, которые не несут смысла для пользователя.
    """

    name = os.path.basename(name or "")
    name = _UNSAFE_NAME_CHARS.sub("_", name).strip()

    return name[:255] or "файл"


def _safe_next_url(target):
    """
    Разрешаем редирект после входа только на внутренние пути
    приложения («/settings»), чтобы нельзя было подсунуть ссылку
    вида /login?next=https://evil.example (open redirect).
    """

    if target and target.startswith("/") and not target.startswith("//") and "\\" not in target:
        return target

    return url_for("routes.dashboard")


def _safe_remove(path):
    try:
        os.remove(path)
    except OSError:
        pass


# ==================================================
# AUTH
# ==================================================

@routes.route("/login", methods=["GET", "POST"])
@csrf_required
def login():

    if session.get("logged_in"):
        return redirect(url_for("routes.dashboard"))

    # пока нет ни одного пользователя, входить некому — предлагаем
    # создать администратора (пароль по умолчанию в проекте не используется)
    if not has_users():
        return redirect(url_for("routes.setup"))

    error = None

    if request.method == "POST":

        if is_locked_out():
            error = "Слишком много неудачных попыток. Попробуйте через минуту."

        else:
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")

            ok, role = check_login(username, password)

            if ok:
                session.clear()
                session["logged_in"] = True
                session["username"] = username
                session["role"] = role
                reset_attempts()
                log_action(username, "login", {"role": role})
                return redirect(_safe_next_url(request.args.get("next")))

            register_failed_attempt()
            log_action(username or "unknown", "login_failed")
            error = "Неверное имя пользователя или пароль."

    return render_template("login.html", error=error)


@routes.route("/setup", methods=["GET", "POST"])
@csrf_required
def setup():
    """
    Первоначальная настройка: задать имя и пароль администратора.
    Доступна только пока в системе нет ни одного пользователя.
    """

    if has_users():
        return redirect(url_for("routes.login"))

    error = None

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("password_confirm", "")

        if password != confirm:
            error = "Пароли не совпадают."
        else:
            try:
                created = create_first_admin(username, password)
            except ValueError as e:
                error = str(e)
            else:
                if created:
                    log_action(username, "initial_admin_created")
                return redirect(url_for("routes.login"))

    return render_template("setup.html", error=error)


@routes.route("/logout")
def logout():
    if session.get("username"):
        log_action(session["username"], "logout")
    session.clear()
    return redirect(url_for("routes.login"))


# ==================================================
# PAGES
# ==================================================

@routes.route("/")
@login_required
def dashboard():
    username = None if session.get("role") == "admin" else session.get("username")
    stats = get_stats(username=username)
    cfg = load_config()
    license_status = get_license_status()
    return render_template("dashboard.html", stats=stats, cfg=cfg, license_status=license_status)


@routes.route("/check")
@login_required
def check_page():
    return render_template("check.html", cfg=load_config())


@routes.route("/files")
@login_required
def files_page():
    return render_template("files.html")


@routes.route("/incidents")
@login_required
def incidents_page():
    username = None if session.get("role") == "admin" else session.get("username")
    logs = list(reversed(get_logs(username=username)))
    return render_template("incidents.html", logs=logs, is_admin=session.get("role") == "admin")


@routes.route("/settings", methods=["GET", "POST"])
@login_required
@csrf_required
def settings_page():

    cfg = load_config()
    message = None
    error = None
    is_admin = session.get("role") == "admin"

    if request.method == "POST":

        form_type = request.form.get("form_type")

        admin_only_forms = {
            "policy", "api_key", "clear_logs", "whitelist",
            "ldap", "notifications", "scan", "ai_providers", "feedback_action"
        }

        if form_type in admin_only_forms and not is_admin:
            error = "Только администратор может изменять эти настройки."

        elif form_type == "policy":

            detectors = {
                "personal": "det_personal" in request.form,
                "company": "det_company" in request.form,
                "bank": "det_bank" in request.form,
                "secrets": "det_secrets" in request.form,
                "address": "det_address" in request.form,
            }

            try:
                min_confidence = float(request.form.get("min_confidence", 0.5))
            except ValueError:
                min_confidence = 0.5

            update_config(
                organization_name=request.form.get("organization_name", "").strip(),
                detectors=detectors,
                min_confidence=min_confidence
            )

            log_action(session["username"], "update_policy", {"detectors": detectors, "min_confidence": min_confidence})
            message = "Настройки политики сохранены."

        elif form_type == "my_password":

            new_password = request.form.get("new_password", "")

            error = validate_password(new_password)

            if not error:
                set_user_password(session["username"], new_password)
                log_action(session["username"], "change_own_password")
                message = "Пароль изменён."

        elif form_type == "api_key":
            regenerate_api_key()
            log_action(session["username"], "regenerate_api_key")
            message = "Новый API-ключ сгенерирован."

        elif form_type == "clear_logs":
            clear_logs()
            log_action(session["username"], "clear_logs")
            message = "Журнал инцидентов очищен."

        elif form_type == "whitelist":

            values = [
                v.strip() for v in request.form.get("whitelist_values", "").splitlines()
                if v.strip()
            ]

            domains = [
                d.strip().lower() for d in request.form.get("whitelist_domains", "").splitlines()
                if d.strip()
            ]

            update_config(whitelist_values=values, whitelist_domains=domains)
            log_action(session["username"], "update_whitelist", {"values": len(values), "domains": len(domains)})
            message = "Список исключений сохранён."

        elif form_type == "ldap":

            ldap_cfg = {
                "enabled": "ldap_enabled" in request.form,
                "server": request.form.get("ldap_server", "").strip(),
                "user_dn_template": request.form.get("ldap_user_dn_template", "{username}").strip(),
                "base_dn": request.form.get("ldap_base_dn", "").strip(),
                "use_ssl": "ldap_use_ssl" in request.form,
                "admin_group_dn": request.form.get("ldap_admin_group_dn", "").strip()
            }

            update_config(ldap=ldap_cfg)
            log_action(session["username"], "update_ldap", {"enabled": ldap_cfg["enabled"]})
            message = "Настройки LDAP сохранены."

        elif form_type == "notifications":

            notif_cfg = dict(cfg.get("notifications", {}))
            notif_cfg.update({
                "email_enabled": "email_enabled" in request.form,
                "smtp_host": request.form.get("smtp_host", "").strip(),
                "smtp_port": int(request.form.get("smtp_port") or 587),
                "smtp_user": request.form.get("smtp_user", "").strip(),
                "smtp_password": request.form.get("smtp_password", "") or notif_cfg.get("smtp_password", ""),
                "smtp_use_tls": "smtp_use_tls" in request.form,
                "email_from": request.form.get("email_from", "").strip(),
                "email_to": request.form.get("email_to", "").strip(),

                "webhook_enabled": "webhook_enabled" in request.form,
                "webhook_url": request.form.get("webhook_url", "").strip(),
                "webhook_format": request.form.get("webhook_format", "json"),

                "syslog_enabled": "syslog_enabled" in request.form,
                "syslog_host": request.form.get("syslog_host", "").strip(),
                "syslog_port": int(request.form.get("syslog_port") or 514),
            })

            update_config(notifications=notif_cfg)
            log_action(session["username"], "update_notifications")
            message = "Настройки уведомлений сохранены."

        elif form_type == "scan":

            extensions = [
                e.strip().lower() for e in request.form.get("scan_extensions", "").split(",")
                if e.strip()
            ]

            scan_cfg = {
                "enabled": "scan_enabled" in request.form,
                "folder": request.form.get("scan_folder", "").strip(),
                "interval_minutes": max(5, int(request.form.get("scan_interval_minutes") or 60)),
                "extensions": extensions or cfg.get("scan", {}).get("extensions", [])
            }

            update_config(scan=scan_cfg)
            log_action(session["username"], "update_scan_settings", {"enabled": scan_cfg["enabled"]})
            message = "Настройки сканирования сохранены. Изменения вступят в силу в течение минуты."

        elif form_type == "ai_providers":

            providers = dict(cfg.get("ai_providers", {}))

            for key in providers:
                providers[key] = dict(providers[key])
                providers[key]["allowed"] = f"provider_{key}" in request.form

            update_config(ai_providers=providers)
            log_action(session["username"], "update_ai_providers_policy")
            message = "Политика AI-сервисов сохранена."

        elif form_type == "feedback_action":

            fb_action = request.form.get("fb_action")
            fb_id = request.form.get("feedback_id", "")

            if fb_action == "remove":
                remove_feedback(fb_id)
                log_action(session["username"], "remove_feedback", {"id": fb_id})
                message = "Отметка удалена — значение снова будет показываться."

            elif fb_action == "promote":

                entries = {e["id"]: e for e in list_feedback()}
                entry = entries.get(fb_id)

                if entry:
                    values = list(cfg.get("whitelist_values", []))
                    if entry["value"] not in values:
                        values.append(entry["value"])
                        update_config(whitelist_values=values)

                    remove_feedback(fb_id)
                    log_action(session["username"], "promote_feedback_to_whitelist", {"value": entry["value"]})
                    message = "Значение перенесено в постоянный список исключений."

        cfg = load_config()

    return render_template(
        "settings.html",
        cfg=cfg,
        message=message,
        error=error,
        is_admin=is_admin,
        ldap_available=ldap_auth.is_available(),
        feedback_entries=list_feedback(limit=100) if is_admin else []
    )


# ==================================================
# HELPERS
# ==================================================

def _source_label():
    return request.headers.get("X-API-Key") and "REST API" or "Веб-интерфейс"


# ==================================================
# ANALYZE (JSON API used by frontend + integrations)
# ==================================================

@routes.route("/api/analyze", methods=["POST"])
@rate_limit(max_calls=60, window_seconds=60, bucket="analyze")
@api_key_required
def api_analyze():

    try:
        register_check()
    except LicenseLimitError as e:
        return jsonify({"error": "license_limit", "detail": str(e)}), 402

    data = request.get_json(silent=True) or {}
    text = data.get("text", "")
    destination = (data.get("destination") or "").strip() or None

    # kind: "text" (запрос перед отправкой в AI) или "ai_response"
    # (проверка того, что AI вернул — см. Модуль 2, п.4 ТЗ:
    # без прокси-режима это делается вставкой ответа вручную)
    kind = data.get("kind", "text")
    source = "ai_response" if kind == "ai_response" else "text"

    settings = load_config()
    result = analyze_text(text, settings)

    provider_blocked = is_provider_blocked(settings, destination)
    action = recommend_action(result.get("risk", "Низкий"), provider_blocked)

    save_incident(
        result.get("findings", []),
        result.get("risk", "Низкий"),
        source=source,
        created_by=session.get("username"),
        destination=destination,
        action=action
    )

    return jsonify({
        "findings": result.get("findings", []),
        "entities": result.get("entities", {}),
        "risk": result.get("risk", "Низкий"),
        "truncated": result.get("truncated", False),
        "action": action,
        "action_label": action_label(action),
        "provider_blocked": provider_blocked
    })


@routes.route("/api/mask", methods=["POST"])
@rate_limit(max_calls=60, window_seconds=60, bucket="mask")
@api_key_required
def api_mask():

    data = request.get_json(silent=True) or {}
    text = data.get("text", "")

    settings = load_config()
    masked = mask_text(text, settings)

    return jsonify({"masked": masked})


@routes.route("/api/feedback", methods=["POST"])
@rate_limit(max_calls=100, window_seconds=60, bucket="feedback")
@login_required
def api_feedback():
    """
    Отметка находки как ложного срабатывания. Требует активную сессию
    (не доступно через голый X-API-Key) — это действие конкретного
    человека, а не автоматизированной интеграции.
    """

    data = request.get_json(silent=True) or {}
    finding_type = (data.get("type") or "").strip()
    value = (data.get("value") or "").strip()

    if not finding_type or not value:
        return jsonify({"error": "Не указан тип или значение находки"}), 400

    mark_false_positive(finding_type, value, username=session.get("username"))
    log_action(session.get("username"), "mark_false_positive", {"type": finding_type})

    return jsonify({"status": "ok"})


@routes.route("/api/report", methods=["POST"])
@rate_limit(max_calls=20, window_seconds=60, bucket="report")
@api_key_required
def api_report():

    try:
        register_check()
    except LicenseLimitError as e:
        return jsonify({"error": "license_limit", "detail": str(e)}), 402

    data = request.get_json(silent=True) or {}
    text = data.get("text", "")
    analyst_name = data.get("analyst_name")
    destination = (data.get("destination") or "").strip() or None

    settings = load_config()
    result = analyze_text(text, settings)

    provider_blocked = is_provider_blocked(settings, destination)
    action = recommend_action(result.get("risk", "Низкий"), provider_blocked)

    save_incident(
        result.get("findings", []),
        result.get("risk", "Низкий"),
        source="report",
        created_by=session.get("username"),
        destination=destination,
        action=action
    )

    file_path = generate_report(
        result.get("findings", []),
        result.get("risk", "Низкий"),
        organization_name=settings.get("organization_name"),
        analyst_name=analyst_name,
        source_label="Проверка текста"
    )

    return send_file(
        file_path,
        as_attachment=True,
        download_name="PromptShield_Report.pdf"
    )


@routes.route("/api/upload", methods=["POST"])
@rate_limit(max_calls=20, window_seconds=60, bucket="upload")
@api_key_required
def api_upload():

    try:
        register_check()
    except LicenseLimitError as e:
        return jsonify({"error": "license_limit", "detail": str(e)}), 402

    if "file" not in request.files:
        return jsonify({"error": "Файл не передан"}), 400

    file = request.files["file"]

    if not file.filename:
        return jsonify({"error": "Файл не выбран"}), 400

    # ВАЖНО: werkzeug.secure_filename() вырезает кириллицу целиком
    # (см. https://github.com/pallets/werkzeug) — «Договор.docx» превратится
    # в «docx» без расширения. Поэтому расширение берём из ИСХОДНОГО имени,
    # а safe_filename используем только для отображения/логирования.
    original_name = file.filename
    ext = os.path.splitext(original_name)[1].lower()
    display_name = safe_display_filename(original_name)

    if ext not in ALLOWED_EXTENSIONS:
        return jsonify({
            "error": f"Формат «{ext or 'без расширения'}» не поддерживается. "
                     f"Поддерживаются: {', '.join(sorted(ALLOWED_EXTENSIONS))}"
        }), 400

    settings = load_config()

    # mkstemp вместо NamedTemporaryFile: на Windows файл, открытый через
    # NamedTemporaryFile(delete=False), остаётся заблокирован до выхода из
    # `with`-блока, и повторная запись в тот же путь через file.save()
    # приводит к PermissionError. mkstemp сразу закрывает дескриптор.
    fd, tmp_path = tempfile.mkstemp(suffix=ext)
    os.close(fd)

    try:
        file.save(tmp_path)
    except Exception:
        _safe_remove(tmp_path)
        return jsonify({"error": "Не удалось сохранить файл для обработки."}), 500

    try:
        # защита от подмены расширения (например, .exe переименован в .docx)
        sig_ok, sig_reason = validate_file_signature(tmp_path, ext)

        if not sig_ok:
            return jsonify({"filename": display_name, "error": sig_reason}), 200

        meta = extract_text_with_meta(tmp_path, ext=ext)

    except Exception as e:
        current_app.logger.exception("file_extractor failed for %s", display_name)
        return jsonify({
            "filename": display_name,
            "error": f"Не удалось прочитать файл: {e}"
        }), 200
    finally:
        _safe_remove(tmp_path)

    text = meta.get("text", "")

    if not text or not text.strip():
        return jsonify({
            "filename": display_name,
            "error": meta.get("warning") or
                     "Не удалось извлечь текст из файла (пустой файл, повреждён "
                     "или защищён паролем)."
        }), 200

    result = analyze_text(text, settings)

    save_incident(
        result.get("findings", []),
        result.get("risk", "Низкий"),
        source="file",
        filename=display_name,
        created_by=session.get("username")
    )

    return jsonify({
        "filename": display_name,
        "findings": result.get("findings", []),
        "entities": result.get("entities", {}),
        "risk": result.get("risk", "Низкий"),
        "truncated": result.get("truncated", False),
        "preview": text[:600],
        "extraction_method": meta.get("method"),
        "extraction_warning": meta.get("warning")
    })


# ==================================================
# STATS / LOGS
# ==================================================

@routes.route("/api/stats", methods=["GET"])
@login_required
def api_stats():
    username = None if session.get("role") == "admin" else session.get("username")
    return jsonify(get_stats(username=username))


@routes.route("/logs", methods=["GET"])
@login_required
def logs():
    username = None if session.get("role") == "admin" else session.get("username")
    return jsonify(get_logs(username=username))


# ==================================================
# ПОЛЬЗОВАТЕЛИ (только admin)
# ==================================================

@routes.route("/users", methods=["GET", "POST"])
@role_required("admin")
@csrf_required
def users_page():

    message = None
    error = None

    if request.method == "POST":

        action = request.form.get("action")

        try:

            if action == "create":

                username = request.form.get("username", "").strip()
                password = request.form.get("password", "")
                role = request.form.get("role", "analyst")

                if not username:
                    error = "Укажите имя пользователя."
                elif validate_password(password):
                    error = validate_password(password)
                else:
                    create_user(username, password, role)
                    log_action(session["username"], "create_user", {"username": username, "role": role})
                    message = f"Пользователь «{username}» создан."

            elif action == "set_role":

                username = request.form.get("username", "")
                role = request.form.get("role", "analyst")

                if role != "admin" and username == session["username"] and count_admins() <= 1:
                    error = "Нельзя снять единственного администратора с этой роли."
                else:
                    set_user_role(username, role)
                    log_action(session["username"], "set_user_role", {"username": username, "role": role})
                    message = f"Роль пользователя «{username}» изменена."

            elif action == "set_active":

                username = request.form.get("username", "")
                active = request.form.get("active") == "1"

                if not active and username == session["username"]:
                    error = "Нельзя деактивировать собственную учётную запись."
                else:
                    set_user_active(username, active)
                    log_action(session["username"], "set_user_active", {"username": username, "active": active})
                    message = "Статус пользователя обновлён."

            elif action == "reset_password":

                username = request.form.get("username", "")
                new_password = request.form.get("password", "")

                if validate_password(new_password):
                    error = validate_password(new_password)
                else:
                    set_user_password(username, new_password)
                    log_action(session["username"], "reset_user_password", {"username": username})
                    message = f"Пароль пользователя «{username}» сброшен."

            elif action == "delete":

                username = request.form.get("username", "")

                if username == session["username"]:
                    error = "Нельзя удалить собственную учётную запись."
                elif count_admins() <= 1 and username != session["username"]:
                    # проверяем только если удаляемый — единственный админ
                    users_now = {u["username"]: u for u in list_users()}
                    if users_now.get(username, {}).get("role") == "admin" and count_admins() <= 1:
                        error = "Нельзя удалить единственного администратора."
                    else:
                        delete_user(username)
                        log_action(session["username"], "delete_user", {"username": username})
                        message = f"Пользователь «{username}» удалён."
                else:
                    delete_user(username)
                    log_action(session["username"], "delete_user", {"username": username})
                    message = f"Пользователь «{username}» удалён."

        except ValueError as e:
            error = str(e)

    return render_template(
        "users.html",
        users=list_users(),
        roles=USER_ROLES,
        message=message,
        error=error
    )


# ==================================================
# АУДИТ (только admin)
# ==================================================

@routes.route("/audit")
@role_required("admin")
def audit_page():
    return render_template("audit.html", entries=get_audit_log())


# ==================================================
# ЛИЦЕНЗИЯ (только admin)
# ==================================================

@routes.route("/license", methods=["GET", "POST"])
@role_required("admin")
@csrf_required
def license_page():

    message = None
    error = None

    if request.method == "POST":

        key = request.form.get("license_key", "").strip()

        try:
            info = activate_license(key)
            log_action(session["username"], "activate_license", {"org": info.get("org")})
            message = f"Лицензия активирована для «{info.get('org')}»."
        except ValueError as e:
            error = str(e)

    return render_template("license.html", status=get_license_status(), message=message, error=error)


# ==================================================
# ФОНОВОЕ СКАНИРОВАНИЕ — статус и ручной запуск (только admin)
# ==================================================

@routes.route("/scan")
@role_required("admin")
def scan_page():
    return render_template("scan.html", status=get_scan_status(), cfg=load_config())


@routes.route("/scan/run", methods=["POST"])
@role_required("admin")
@csrf_required
def scan_run():
    ok, msg = run_scan_now()
    log_action(session["username"], "run_scan_now", {"ok": ok})
    return redirect(url_for("routes.scan_page"))


# ==================================================
# РЕЗЕРВНОЕ КОПИРОВАНИЕ (только admin)
#
# Бэкап содержит config.json (включая API-ключ и хэши паролей) и
# журнал инцидентов. Файл создаётся и отдаётся локально через браузер —
# приложение не отправляет его никуда по сети.
# ==================================================

@routes.route("/backup")
@role_required("admin")
def backup_page():
    return render_template("backup.html", backups=list_backups())


@routes.route("/backup/create", methods=["POST"])
@role_required("admin")
@csrf_required
def backup_create():

    filepath = create_backup()
    log_action(session["username"], "create_backup", {"file": os.path.basename(filepath)})

    return send_file(filepath, as_attachment=True, download_name=os.path.basename(filepath))


@routes.route("/backup/restore", methods=["POST"])
@role_required("admin")
@csrf_required
def backup_restore():

    if "backup_file" not in request.files or not request.files["backup_file"].filename:
        return redirect(url_for("routes.backup_page", error="Файл не выбран"))

    file = request.files["backup_file"]

    fd, tmp_path = tempfile.mkstemp(suffix=".zip")
    os.close(fd)

    try:
        file.save(tmp_path)
        restore_backup(tmp_path)
        log_action(session["username"], "restore_backup")

        # после восстановления базы/конфига текущая сессия может уже
        # не соответствовать новому состоянию пользователей — просим
        # войти заново, это безопаснее, чем оставить как есть
        session.clear()

        return redirect(url_for("routes.login"))

    except ValueError as e:
        return render_template("backup.html", backups=list_backups(), error=str(e))

    finally:
        _safe_remove(tmp_path)


# ==================================================
# ОТЧЁТНОСТЬ: активность пользователей + сводные отчёты за период
# (дневной / недельный / для руководителя ИБ)
# ==================================================

PERIOD_DAYS = {"day": 1, "week": 7, "month": 30}
PERIOD_LABELS = {"day": "за сутки", "week": "за неделю", "month": "за месяц (для руководителя ИБ)"}


@routes.route("/reports")
@role_required("admin")
def reports_page():
    stats = get_stats(days=30)
    activity = get_user_activity(days=30)
    return render_template("reports.html", stats=stats, activity=activity)


@routes.route("/reports/generate", methods=["POST"])
@role_required("admin")
@csrf_required
def reports_generate():

    period = request.form.get("period", "week")
    fmt = request.form.get("format", "pdf")

    days = PERIOD_DAYS.get(period, 7)
    label = PERIOD_LABELS.get(period, period)

    stats = get_stats(days=days)
    activity = get_user_activity(days=days)

    log_action(session["username"], "generate_summary_report", {"period": period, "format": fmt})

    if fmt == "xlsx":
        file_path = export_summary_xlsx(stats, activity, label)
        download_name = "PromptShield_Summary.xlsx"

    elif fmt == "json":
        import json
        from datetime import datetime as _dt

        payload = {"period": label, "stats": stats, "activity": activity}
        filename = _dt.now().strftime("PromptShield_Summary_%Y%m%d_%H%M%S.json")
        file_path = data_path("reports", filename)

        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)

        download_name = "PromptShield_Summary.json"

    else:
        settings = load_config()
        file_path = generate_summary_report(stats, activity, label, settings.get("organization_name"))
        download_name = "PromptShield_Summary.pdf"

    return send_file(file_path, as_attachment=True, download_name=download_name)


@routes.route("/reports/export-incidents", methods=["POST"])
@role_required("admin")
@csrf_required
def reports_export_incidents():

    logs = get_logs(limit=5000)
    log_action(session["username"], "export_incidents_xlsx")
    file_path = export_incidents_xlsx(logs)

    return send_file(file_path, as_attachment=True, download_name="PromptShield_Incidents.xlsx")


# ==================================================
# HEALTH / METRICS (для мониторинга, без авторизации —
# это стандартная практика для liveness/readiness проб и
# Prometheus-скрейпинга; рекомендуется закрыть доступ к этим
# путям на уровне сетевого экрана/firewall в продакшене)
# ==================================================

@routes.route("/health")
def health():
    return jsonify({"status": "ok", "service": "promptshield"})


@routes.route("/metrics")
def metrics():

    stats = get_stats(days=36500)

    lines = [
        "# HELP promptshield_checks_total Total number of checks performed",
        "# TYPE promptshield_checks_total counter",
        f'promptshield_checks_total {stats["total_checks"]}',
        "# HELP promptshield_risk_count Checks by risk level",
        "# TYPE promptshield_risk_count gauge",
    ]

    for risk, count in stats["risk_counts"].items():
        lines.append(f'promptshield_risk_count{{risk="{risk}"}} {count}')

    return "\n".join(lines) + "\n", 200, {"Content-Type": "text/plain; version=0.0.4"}
