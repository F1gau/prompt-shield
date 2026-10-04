from detectors.personal_detector import find_personal_data
from detectors.address_detector import find_addresses
from detectors.company_detector import find_company_details
from detectors.bank_detector import find_bank_details
from detectors.secret_detector import find_secrets
from detectors.prompt_injection_detector import find_prompt_injections

from core.entity_builder import build_entities
from core.config import load_config
from core.ner import merge_ner_findings
from core.feedback import get_suppressed_set


# ==================================================
# КАТЕГОРИИ ДЕТЕКТОРОВ (для включения/выключения в настройках)
# ==================================================

DETECTOR_CATEGORY = {
    "ФИО": "personal", "EMAIL": "personal", "PHONE": "personal",
    "PASSPORT": "personal", "SNILS": "personal", "BIRTH_DATE": "personal",
    "INN_PERSON": "personal",

    "АДРЕС": "address",

    "ОРГАНИЗАЦИЯ": "company", "INN_ORG": "company", "KPP": "company",
    "OGRN": "company", "CORPORATE_EMAIL": "company",

    "BIK": "bank", "ACCOUNT": "bank", "CORRESPONDENT_ACCOUNT": "bank", "CARD_NUMBER": "bank",

    "API_KEY": "secrets", "SECRET_KEY": "secrets", "ACCESS_TOKEN": "secrets",
    "BEARER_TOKEN": "secrets", "JWT_TOKEN": "secrets", "GITHUB_TOKEN": "secrets",
    "AWS_KEY": "secrets", "TELEGRAM_TOKEN": "secrets", "PRIVATE_KEY": "secrets",
    "PASSWORD": "secrets", "CREDENTIALS": "secrets",

    "IP": "secrets",

    "PROMPT_INJECTION": "prompt_injection"
}


# ==================================================
# RISK WEIGHTS
# ==================================================

RISK_WEIGHT = {
    "ФИО": 2,
    "EMAIL": 1,
    "PHONE": 1,
    "PASSPORT": 4,
    "SNILS": 4,
    "BIRTH_DATE": 2,
    "INN_PERSON": 3,

    "АДРЕС": 2,

    "ОРГАНИЗАЦИЯ": 1,
    "INN_ORG": 2,
    "KPP": 1,
    "OGRN": 1,
    "CORPORATE_EMAIL": 1,

    "ACCOUNT": 5,
    "CORRESPONDENT_ACCOUNT": 5,
    "BIK": 2,
    "CARD_NUMBER": 6,

    "API_KEY": 7,
    "SECRET_KEY": 7,
    "ACCESS_TOKEN": 8,
    "BEARER_TOKEN": 8,
    "JWT_TOKEN": 8,
    "GITHUB_TOKEN": 8,
    "AWS_KEY": 9,
    "TELEGRAM_TOKEN": 9,
    "PRIVATE_KEY": 10,
    "PASSWORD": 8,
    "CREDENTIALS": 7,

    "IP": 1,

    # Попытка prompt injection — это не пассивная утечка данных, а
    # активная атака на модель. Одного совпадения уже достаточно,
    # чтобы поднять риск минимум до "Высокий" независимо от остальных
    # находок в тексте.
    "PROMPT_INJECTION": 15
}


# ==================================================
# NORMALIZE TO STRICT CONTRACT
# ==================================================

def to_item(v):

    if isinstance(v, dict):

        return {
            "value": str(v.get("value")),
            "confidence": float(v.get("confidence", 1.0))
        }

    return {
        "value": str(v),
        "confidence": 1.0
    }


def normalize_items(items):

    if not items:
        return []

    if not isinstance(items, list):
        items = [items]

    result = []

    for i in items:

        item = to_item(i)

        if item["value"]:
            result.append(item)

    return result


def normalize_findings(findings):

    result = []

    for item in findings:

        t = item.get("type")
        items = normalize_items(item.get("items"))

        if not items:
            continue

        result.append({
            "type": t,
            "items": items,
            "count": len(items)
        })

    return result


# ==================================================
# DEDUP (SAFE + STABLE)
# ==================================================

def remove_duplicates(findings):

    seen = set()
    result = []

    for item in findings:

        t = item.get("type")

        values = sorted(
            i["value"]
            for i in item.get("items", [])
            if i.get("value")
        )

        key = (t, tuple(values))

        if key in seen:
            continue

        seen.add(key)
        result.append(item)

    return result


# ==================================================
# CONFIDENCE THRESHOLD FILTER
# ==================================================

def filter_by_confidence(findings, min_confidence):

    if not min_confidence:
        return findings

    result = []

    for item in findings:

        items = [
            i for i in item.get("items", [])
            if float(i.get("confidence", 1.0)) >= min_confidence
        ]

        if not items:
            continue

        result.append({
            "type": item.get("type"),
            "items": items,
            "count": len(items)
        })

    return result


# ==================================================
# WHITELIST FILTER
#
# Позволяет организации сказать «это не утечка» — например,
# собственный корпоративный домен или тестовые/демонстрационные
# значения, которые иначе постоянно попадали бы в отчёты.
# ==================================================

EMAIL_LIKE_TYPES = {"EMAIL", "CORPORATE_EMAIL"}


def filter_by_whitelist(findings, whitelist_values=None, whitelist_domains=None):

    if not whitelist_values and not whitelist_domains:
        return findings

    values_set = {v.strip().lower() for v in (whitelist_values or []) if v.strip()}
    domains_set = {d.strip().lower() for d in (whitelist_domains or []) if d.strip()}

    result = []

    for item in findings:

        item_type = item.get("type")
        kept = []

        for entry in item.get("items", []):

            value = str(entry.get("value", "")).strip()
            value_lower = value.lower()

            if value_lower in values_set:
                continue

            if item_type in EMAIL_LIKE_TYPES and "@" in value and domains_set:
                domain = value_lower.rsplit("@", 1)[-1]
                if domain in domains_set:
                    continue

            kept.append(entry)

        if not kept:
            continue

        result.append({
            "type": item_type,
            "items": kept,
            "count": len(kept)
        })

    return result


def filter_by_feedback(findings, suppressed_set):
    """
    Убирает находки, которые пользователи ранее отметили как ложные
    срабатывания (см. core/feedback.py). В отличие от filter_by_whitelist
    (заполняется вручную администратором в Настройках), здесь список
    накапливается динамически по мере использования приложения.
    """

    if not suppressed_set:
        return findings

    result = []

    for item in findings:

        item_type = item.get("type")
        kept = []

        for entry in item.get("items", []):

            value_lower = str(entry.get("value", "")).strip().lower()

            if (item_type, value_lower) in suppressed_set:
                continue

            kept.append(entry)

        if not kept:
            continue

        result.append({
            "type": item_type,
            "items": kept,
            "count": len(kept)
        })

    return result


# ==================================================
# RISK CALCULATION
# ==================================================

def calculate_risk(findings):

    score = 0

    for item in findings:

        t = item.get("type")
        weight = RISK_WEIGHT.get(t, 1)

        for i in item.get("items", []):

            score += weight * float(i.get("confidence", 1.0))

    if score >= 25:
        return "Критический"

    if score >= 12:
        return "Высокий"

    if score >= 5:
        return "Средний"

    return "Низкий"


# ==================================================
# MAIN ANALYZER
# ==================================================

def analyze_text(text, settings=None):

    if settings is None:
        settings = load_config()

    if not text or not text.strip():
        return {
            "findings": [],
            "entities": {},
            "risk": "Низкий",
            "truncated": False
        }

    # -------------------------
    # DоS-ЗАЩИТА: ограничение размера входного текста
    # -------------------------

    max_len = settings.get("max_text_length", 200000)
    truncated = False

    if len(text) > max_len:
        text = text[:max_len]
        truncated = True

    detectors_cfg = settings.get("detectors", {})

    def enabled(category):
        return detectors_cfg.get(category, True)

    findings = []

    # -------------------------
    # DETECTORS
    # -------------------------

    if enabled("company"):
        findings.extend(find_company_details(text) or [])

    if enabled("address"):
        addresses = find_addresses(text) or []
        if addresses:
            findings.append({
                "type": "АДРЕС",
                "items": addresses
            })

    if enabled("bank"):
        findings.extend(find_bank_details(text) or [])

    if enabled("secrets"):
        findings.extend(find_secrets(text) or [])

    if enabled("personal"):
        findings.extend(find_personal_data(text) or [])

    if enabled("prompt_injection"):
        findings.extend(find_prompt_injections(text) or [])

    # -------------------------
    # NER (опционально, если установлен natasha) — добираем ФИО и
    # организации, которые могли пропустить строгие regex-шаблоны
    # -------------------------

    if enabled("personal") or enabled("company"):
        findings = merge_ner_findings(text, findings, settings)

    # -------------------------
    # PIPELINE CLEAN
    # -------------------------

    findings = normalize_findings(findings)
    findings = remove_duplicates(findings)
    findings = filter_by_confidence(findings, settings.get("min_confidence", 0))
    findings = filter_by_whitelist(
        findings,
        settings.get("whitelist_values"),
        settings.get("whitelist_domains")
    )
    findings = filter_by_feedback(findings, get_suppressed_set())

    # -------------------------
    # ENTITIES
    # -------------------------

    entities = build_entities(findings)

    # -------------------------
    # RISK
    # -------------------------

    risk = calculate_risk(findings)

    return {
        "findings": findings,
        "entities": entities,
        "risk": risk,
        "truncated": truncated
    }