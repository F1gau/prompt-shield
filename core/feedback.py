"""
Обратная связь по ложным срабатываниям.

Идея: статический whitelist (Настройки → Список исключений) требует,
чтобы администратор заранее знал и вручную вписал значение. На
практике аналитик видит ложное срабатывание прямо в результатах
проверки и хочет одним кликом сказать "это не утечка" — без похода
в настройки. Это ровно то, что делает данный модуль: отметка
сохраняется, и при последующих проверках то же значение того же типа
больше не показывается как находка.

Администратор видит накопленные отметки в Настройках и может либо
удалить отметку (если она ошибочна), либо ничего не делать —
подавление уже работает само по себе с момента отметки.
"""

import uuid
import logging
from datetime import datetime

from core.db import get_conn, init_db


logger = logging.getLogger("promptshield.feedback")


def mark_false_positive(finding_type, value, username=None):

    init_db()

    value = str(value).strip()

    if not value or not finding_type:
        return None

    entry = {
        "id": str(uuid.uuid4()),
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "username": username,
        "type": finding_type,
        "value": value,
        "value_lower": value.lower()
    }

    with get_conn() as conn:

        # избегаем дублей: если то же значение того же типа уже
        # отмечено — просто не создаём вторую запись
        existing = conn.execute(
            "SELECT id FROM feedback WHERE type = ? AND value_lower = ?",
            (entry["type"], entry["value_lower"])
        ).fetchone()

        if existing:
            return existing["id"]

        conn.execute(
            """
            INSERT INTO feedback (id, timestamp, username, type, value, value_lower)
            VALUES (:id, :timestamp, :username, :type, :value, :value_lower)
            """,
            entry
        )

    return entry["id"]


def get_suppressed_set():
    """
    Возвращает множество (type, value_lower) — эти находки нужно
    исключать из результатов анализа, аналогично статическому
    whitelist, но накопленное пользователями динамически.
    """

    init_db()

    with get_conn() as conn:
        rows = conn.execute("SELECT type, value_lower FROM feedback").fetchall()

    return {(r["type"], r["value_lower"]) for r in rows}


def list_feedback(limit=500):

    init_db()

    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM feedback ORDER BY timestamp DESC LIMIT ?",
            (limit,)
        ).fetchall()

    return [dict(r) for r in rows]


def remove_feedback(feedback_id):

    init_db()

    with get_conn() as conn:
        conn.execute("DELETE FROM feedback WHERE id = ?", (feedback_id,))


def count_feedback():

    init_db()

    with get_conn() as conn:
        return conn.execute("SELECT COUNT(*) FROM feedback").fetchone()[0]
