import json
import uuid
import logging
from datetime import datetime, timedelta

from core.db import get_conn, init_db, row_to_dict
from core.config import load_config
from core.notifications import notify_incident

logger = logging.getLogger("promptshield.logger")


# ==================================================
# SAVE INCIDENT
#
# В журнал попадают только метаданные (тип риска, типы найденных
# сущностей, их количество). Сами значения (номера паспортов,
# токены и т.д.) НЕ сохраняются — принципиальный момент для
# клиентов из сферы информационной безопасности.
# ==================================================

def save_incident(findings, risk, source="text", filename=None, created_by=None, destination=None, action=None):

    init_db()

    total = 0

    for item in findings:
        for v in item.get("items", []):
            if isinstance(v, dict):
                total += v.get("confidence", 1.0)
            else:
                total += 1

    incident = {
        "id": str(uuid.uuid4()),
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "risk": risk,
        "total": round(total, 3),
        "findings_count": sum(item.get("count", 0) for item in findings),
        "types": sorted(set(item.get("type") for item in findings if item.get("type"))),
        "source": source,
        "filename": filename,
        "created_by": created_by,
        "destination": destination,
        "action": action
    }

    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO incidents (id, timestamp, risk, total, findings_count, types, source, filename, created_by, destination, action)
            VALUES (:id, :timestamp, :risk, :total, :findings_count, :types, :source, :filename, :created_by, :destination, :action)
            """,
            {**incident, "types": json.dumps(incident["types"], ensure_ascii=False)}
        )

    try:
        cfg = load_config()
        notify_incident(incident, cfg.get("notifications", {}), cfg.get("organization_name", "PromptShield"))
    except Exception:
        logger.exception("Ошибка при рассылке уведомлений об инциденте")

    return incident


def get_logs(limit=500, username=None):
    """
    username=None -> все записи (для admin). Если передан username,
    возвращаются только инциденты этого пользователя (роль analyst
    видит только свою историю проверок, а не всей компании)."""

    init_db()

    with get_conn() as conn:

        if username:
            rows = conn.execute(
                "SELECT * FROM incidents WHERE created_by = ? ORDER BY timestamp DESC LIMIT ?",
                (username, limit)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM incidents ORDER BY timestamp DESC LIMIT ?",
                (limit,)
            ).fetchall()

    return [row_to_dict(r) for r in rows]


# ==================================================
# STATS FOR DASHBOARD
# ==================================================

def get_stats(days=30, username=None):

    init_db()

    cutoff = (datetime.now() - timedelta(days=days)).isoformat(timespec="seconds")

    with get_conn() as conn:

        if username:
            total_checks = conn.execute(
                "SELECT COUNT(*) FROM incidents WHERE created_by = ?", (username,)
            ).fetchone()[0]

            recent_rows = conn.execute(
                "SELECT * FROM incidents WHERE timestamp >= ? AND created_by = ? ORDER BY timestamp ASC",
                (cutoff, username)
            ).fetchall()
        else:
            total_checks = conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]

            recent_rows = conn.execute(
                "SELECT * FROM incidents WHERE timestamp >= ? ORDER BY timestamp ASC",
                (cutoff,)
            ).fetchall()

    recent = [row_to_dict(r) for r in recent_rows]

    risk_counts = {"Низкий": 0, "Средний": 0, "Высокий": 0, "Критический": 0}
    type_counts = {}
    timeline = {}

    for item in recent:

        risk = item.get("risk", "Низкий")
        risk_counts[risk] = risk_counts.get(risk, 0) + 1

        for t in item.get("types", []):
            type_counts[t] = type_counts.get(t, 0) + 1

        day = item.get("timestamp", "")[:10]
        timeline[day] = timeline.get(day, 0) + 1

    top_types = sorted(
        type_counts.items(),
        key=lambda x: x[1],
        reverse=True
    )[:8]

    return {
        "total_checks": total_checks,
        "checks_period": len(recent),
        "risk_counts": risk_counts,
        "top_types": top_types,
        "timeline": sorted(timeline.items()),
        "high_risk_ratio": round(
            (risk_counts.get("Высокий", 0) + risk_counts.get("Критический", 0))
            / len(recent) * 100, 1
        ) if recent else 0.0
    }


def clear_logs():

    init_db()

    with get_conn() as conn:
        conn.execute("DELETE FROM incidents")


# ==================================================
# АКТИВНОСТЬ ПОЛЬЗОВАТЕЛЕЙ И ОЦЕНКА РИСКА
#
# Формула сознательно простая и объясняемая (не выдаётся за точную
# научную метрику): средний вес риска по всем проверкам пользователя,
# скорректированный долей проверок с высоким/критическим риском.
# В интерфейсе это подписано как "ориентировочная оценка".
# ==================================================

_RISK_WEIGHT = {"Низкий": 5, "Средний": 35, "Высокий": 70, "Критический": 100}


def _compute_risk_score(risk_counts, total):

    if not total:
        return 0

    weighted_sum = sum(_RISK_WEIGHT.get(r, 0) * c for r, c in risk_counts.items())
    base = weighted_sum / total

    violations = risk_counts.get("Высокий", 0) + risk_counts.get("Критический", 0)
    violation_ratio = violations / total

    score = base * 0.7 + violation_ratio * 100 * 0.3

    return min(100, round(score))


def get_user_activity(days=30):

    init_db()

    cutoff = (datetime.now() - timedelta(days=days)).isoformat(timespec="seconds")

    with get_conn() as conn:
        rows = conn.execute(
            "SELECT created_by, risk FROM incidents WHERE timestamp >= ? AND created_by IS NOT NULL",
            (cutoff,)
        ).fetchall()

    per_user = {}

    for row in rows:

        user = row["created_by"]
        risk = row["risk"]

        entry = per_user.setdefault(user, {"total": 0, "risk_counts": {}})
        entry["total"] += 1
        entry["risk_counts"][risk] = entry["risk_counts"].get(risk, 0) + 1

    result = []

    for user, entry in per_user.items():

        violations = entry["risk_counts"].get("Высокий", 0) + entry["risk_counts"].get("Критический", 0)

        result.append({
            "username": user,
            "total_checks": entry["total"],
            "violations": violations,
            "risk_score": _compute_risk_score(entry["risk_counts"], entry["total"])
        })

    result.sort(key=lambda x: x["risk_score"], reverse=True)

    return result
