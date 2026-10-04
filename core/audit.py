import uuid
import json
from datetime import datetime

from core.db import get_conn, init_db


def log_action(username, action, details=None):

    init_db()

    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO audit_log (id, timestamp, username, action, details)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                str(uuid.uuid4()),
                datetime.now().isoformat(timespec="seconds"),
                username or "system",
                action,
                json.dumps(details, ensure_ascii=False) if details else None
            )
        )


def get_audit_log(limit=300):

    init_db()

    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ?",
            (limit,)
        ).fetchall()

    result = []

    for r in rows:
        d = dict(r)
        if d.get("details"):
            try:
                d["details"] = json.loads(d["details"])
            except (ValueError, TypeError):
                pass
        result.append(d)

    return result
