import os
import logging
from logging.handlers import RotatingFileHandler

from flask import Flask, jsonify, render_template, request, session

from core.routes import routes
from core.config import load_config
from core.auth import csrf_token
from core.db import init_db
from core.users import bootstrap_admin_from_env
from core.license import get_license_status
from core.scheduler import start_scheduler
from core.paths import data_path, resource_path


def setup_logging(app):

    handler = RotatingFileHandler(
        data_path("logs", "app.log"),
        maxBytes=5 * 1024 * 1024,
        backupCount=3,
        encoding="utf-8"
    )

    handler.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    ))

    handler.setLevel(logging.INFO)

    app.logger.addHandler(handler)
    app.logger.setLevel(logging.INFO)

    # снижаем болтливость werkzeug-логов запросов, но не убираем совсем
    logging.getLogger("werkzeug").setLevel(logging.WARNING)


def register_error_handlers(app):

    @app.errorhandler(400)
    def bad_request(e):
        if request.path.startswith("/api/"):
            return jsonify({"error": "bad_request", "detail": str(e.description)}), 400
        return render_template("error.html", code=400, message=e.description), 400

    @app.errorhandler(401)
    def unauthorized(e):
        if request.path.startswith("/api/"):
            return jsonify({"error": "unauthorized"}), 401
        return render_template("error.html", code=401, message="Требуется авторизация."), 401

    @app.errorhandler(404)
    def not_found(e):
        if request.path.startswith("/api/"):
            return jsonify({"error": "not_found"}), 404
        return render_template("error.html", code=404, message="Страница не найдена."), 404

    @app.errorhandler(413)
    def too_large(e):
        max_mb = app.config.get("MAX_CONTENT_LENGTH", 0) // (1024 * 1024)
        detail = f"Файл превышает допустимый размер ({max_mb} МБ)."
        if request.path.startswith("/api/"):
            return jsonify({"error": "payload_too_large", "detail": detail}), 413
        return render_template("error.html", code=413, message=detail), 413

    @app.errorhandler(500)
    def internal_error(e):
        app.logger.exception("Internal server error")
        if request.path.startswith("/api/"):
            return jsonify({"error": "internal_error"}), 500
        return render_template("error.html", code=500, message="Внутренняя ошибка сервера."), 500


def create_app():

    app = Flask(
        __name__,
        template_folder=resource_path("templates"),
        static_folder=resource_path("static")
    )

    cfg = load_config()

    app.secret_key = cfg.get("secret_key")

    # ограничение размера загружаемых файлов (защита от DoS)
    app.config["MAX_CONTENT_LENGTH"] = cfg.get("max_upload_mb", 15) * 1024 * 1024

    # безопасные настройки cookie для сессии
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    # Secure-флаг нужен при работе по HTTPS (за reverse proxy); по умолчанию
    # выключен, иначе вход по http://127.0.0.1 в браузере не заработает.
    app.config["SESSION_COOKIE_SECURE"] = os.environ.get("PROMPTSHIELD_COOKIE_SECURE", "0") == "1"

    setup_logging(app)
    init_db()
    bootstrap_admin_from_env()
    start_scheduler()

    app.register_blueprint(routes)

    @app.context_processor
    def inject_csrf():
        return {"csrf_token": csrf_token}

    @app.context_processor
    def inject_trial_banner():

        if not session.get("logged_in"):
            return {"trial_banner": None}

        try:
            status = get_license_status()
        except Exception:
            return {"trial_banner": None}

        if status.get("mode") != "trial":
            if status.get("mode") == "licensed" and status.get("expired"):
                return {"trial_banner": f"Лицензия истекла {status.get('expires')}. Работа заблокирована."}
            return {"trial_banner": None}

        if status.get("blocked"):
            return {"trial_banner": "Пробный период закончился. Проверки заблокированы."}

        return {"trial_banner": (
            f"Пробный период: осталось {status['days_left']} дн. "
            f"и {status['checks_left']} проверок из {status['checks_max']}."
        )}

    register_error_handlers(app)

    return app


app = create_app()


if __name__ == "__main__":

    from core.paths import is_frozen

    debug_mode = os.environ.get("PROMPTSHIELD_DEBUG", "0") == "1"
    host = os.environ.get("PROMPTSHIELD_HOST", "127.0.0.1")
    port = int(os.environ.get("PROMPTSHIELD_PORT", "5000"))

    # В собранном .exe используем production-сервер (waitress) по
    # умолчанию — иначе пользователь увидит предупреждение "development
    # server" от Flask, что выглядит непрофессионально для готового
    # коммерческого продукта. При обычном запуске из исходников
    # поведение прежнее (можно явно включить через переменную окружения).
    default_production = "1" if is_frozen() else "0"
    use_production_server = os.environ.get("PROMPTSHIELD_PRODUCTION", default_production) == "1"

    print("=" * 60)
    print(" ПРОМПТ-ЩИТ запущен")
    print(f" Откройте в браузере: http://{host}:{port}")
    print(" Первый запуск: задайте пароль администратора в браузере")
    print(" (или через PROMPTSHIELD_ADMIN_PASSWORD до запуска).")
    print("=" * 60)

    if is_frozen():
        # автоматически открываем браузер — так собранный .exe
        # ощущается как обычное десктоп-приложение, а не сервер,
        # который нужно отдельно "открывать руками"
        import threading
        import webbrowser

        def _open_browser():
            import time
            time.sleep(1.5)
            webbrowser.open(f"http://{host}:{port}")

        threading.Thread(target=_open_browser, daemon=True).start()

    if use_production_server:
        # waitress — production-ready WSGI сервер, кроссплатформенный
        # (в т.ч. корректно работает на Windows, в отличие от gunicorn)
        from waitress import serve
        serve(app, host=host, port=port)
    else:
        app.run(host=host, port=port, debug=debug_mode, threaded=True)
