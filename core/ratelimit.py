import time
import secrets
import threading
from functools import wraps

from flask import request, jsonify, session


_LOCK = threading.Lock()

# {client_key: {bucket_name: [timestamps]}}
_HITS = {}


def _client_key():
    """
    Идентифицируем клиента по API-ключу (для внешних интеграций),
    либо по идентификатору сессии (для веб-интерфейса) — это важно
    в офисе, где много сотрудников работают из-за одного NAT/IP:
    без привязки к сессии они делили бы один лимит на всех.
    """

    api_key = request.headers.get("X-API-Key")

    if api_key:
        return f"key:{api_key}"

    if "logged_in" in session:

        if "_rl_id" not in session:
            session["_rl_id"] = secrets.token_hex(8)

        return f"session:{session['_rl_id']}"

    return f"ip:{request.remote_addr or 'unknown'}"


def rate_limit(max_calls, window_seconds, bucket="default"):
    """
    Декоратор: не более max_calls вызовов за window_seconds секунд
    для одного клиента. При превышении — 429 Too Many Requests.
    """

    def decorator(view):

        @wraps(view)
        def wrapped(*args, **kwargs):

            key = _client_key()
            now = time.time()

            with _LOCK:

                client_buckets = _HITS.setdefault(key, {})
                hits = client_buckets.setdefault(bucket, [])

                # чистим устаревшие метки времени
                cutoff = now - window_seconds
                while hits and hits[0] < cutoff:
                    hits.pop(0)

                if len(hits) >= max_calls:
                    retry_after = max(1, int(window_seconds - (now - hits[0])))
                    return jsonify({
                        "error": "rate_limited",
                        "detail": f"Слишком много запросов. Повторите через {retry_after} сек."
                    }), 429, {"Retry-After": str(retry_after)}

                hits.append(now)

            return view(*args, **kwargs)

        return wrapped

    return decorator
