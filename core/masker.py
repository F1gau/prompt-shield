import re

from detectors.personal_detector import find_personal_data
from detectors.address_detector import find_addresses
from detectors.company_detector import find_company_details
from detectors.bank_detector import find_bank_details
from detectors.secret_detector import find_secrets

from core.config import load_config


# ==================================================
# MASK MAP
# ==================================================

MASK_NAMES = {
    "ФИО": "[ФИО]",
    "EMAIL": "[EMAIL]",
    "PHONE": "[ТЕЛЕФОН]",
    "PASSPORT": "[ПАСПОРТ]",
    "SNILS": "[СНИЛС]",
    "BIRTH_DATE": "[ДАТА_РОЖДЕНИЯ]",
    "INN_PERSON": "[ИНН_ФИЗЛИЦА]",

    "АДРЕС": "[АДРЕС]",

    "ОРГАНИЗАЦИЯ": "[ОРГАНИЗАЦИЯ]",
    "INN_ORG": "[ИНН_ОРГАНИЗАЦИИ]",
    "KPP": "[КПП]",
    "OGRN": "[ОГРН]",
    "CORPORATE_EMAIL": "[КОРПОРАТИВНАЯ_ПОЧТА]",

    "BIK": "[БИК]",
    "ACCOUNT": "[РАСЧЕТНЫЙ_СЧЕТ]",
    "CORRESPONDENT_ACCOUNT": "[КОРРЕСПОНДЕНТСКИЙ_СЧЕТ]",
    "CARD_NUMBER": "[НОМЕР_КАРТЫ]",

    "API_KEY": "[API_KEY]",
    "SECRET_KEY": "[SECRET_KEY]",
    "ACCESS_TOKEN": "[ACCESS_TOKEN]",
    "BEARER_TOKEN": "[BEARER_TOKEN]",
    "JWT_TOKEN": "[JWT_TOKEN]",
    "GITHUB_TOKEN": "[GITHUB_TOKEN]",
    "AWS_KEY": "[AWS_KEY]",
    "TELEGRAM_TOKEN": "[TELEGRAM_TOKEN]",
    "PRIVATE_KEY": "[PRIVATE_KEY]",
    "PASSWORD": "[PASSWORD]",
    "CREDENTIALS": "[CREDENTIALS]",

    "IP": "[IP]"
}


# ==================================================
# SAFE VALUE EXTRACTOR
# ==================================================

def extract_value(v):
    if isinstance(v, dict):
        return v.get("value")
    return str(v) if v is not None else None


# ==================================================
# NORMALIZE FINDINGS
# ==================================================

def collect_findings(text, settings=None):

    if settings is None:
        settings = load_config()

    detectors_cfg = settings.get("detectors", {})

    def enabled(category):
        return detectors_cfg.get(category, True)

    findings = []

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

    return findings


# ==================================================
# PRIVATE KEY FIX (CRITICAL)
# ==================================================

def mask_private_keys(text):
    pattern = r"-----BEGIN [A-Z ]+PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+PRIVATE KEY-----"
    return re.sub(pattern, "[PRIVATE_KEY]", text)


# ==================================================
# BUILD SPANS
# ==================================================

def build_spans(text, findings):

    spans = []
    seen = set()

    for item in findings:

        item_type = item.get("type")
        mask = MASK_NAMES.get(item_type)

        if not mask:
            continue

        for raw_value in item.get("items", []):

            value = extract_value(raw_value)

            if not value:
                continue

            value = str(value)

            if item_type == "CARD_NUMBER":
                # CARD_NUMBER хранится в findings уже без пробелов/дефисов
                # (нормализовано для проверки алгоритма Луна), но в самом
                # тексте номер мог быть написан как "4111 1111 1111 1111" —
                # обычный литеральный поиск такую запись не найдёт.
                # Допускаем необязательный пробел/дефис МЕЖДУ каждой цифрой.
                pattern = r"[ -]?".join(re.escape(ch) for ch in value)
            elif item_type == "ОРГАНИЗАЦИЯ":
                # детектор нормализует «ООО "Ромашка"» до «ООО Ромашка»;
                # в исходном тексте между словами могут стоять кавычки
                # (и закрывающая кавычка после названия)
                pattern = r"[\s\"«»]*".join(map(re.escape, value.split())) + r"[\"»]?"
            else:
                # whitespace-tolerant matching для многословных значений
                pattern = r"\s*".join(map(re.escape, value.split()))

            if not pattern:
                continue

            for match in re.finditer(pattern, text):

                key = (match.start(), match.end(), mask)

                if key in seen:
                    continue

                seen.add(key)

                spans.append({
                    "start": match.start(),
                    "end": match.end(),
                    "mask": mask
                })

    return spans


# ==================================================
# MERGE OVERLAPS
# ==================================================

def merge_spans(spans):

    if not spans:
        return []

    spans.sort(key=lambda x: (x["start"], -x["end"]))

    merged = []

    for span in spans:

        if not merged:
            merged.append(span)
            continue

        last = merged[-1]

        if span["start"] <= last["end"]:

            if span["end"] > last["end"]:
                last["end"] = span["end"]
                last["mask"] = span["mask"]

        else:
            merged.append(span)

    return merged


# ==================================================
# APPLY MASK
# ==================================================

def apply_mask(text, spans):

    if not spans:
        return text

    result = []
    last = 0

    for span in spans:
        result.append(text[last:span["start"]])
        result.append(span["mask"])
        last = span["end"]

    result.append(text[last:])

    return "".join(result)


# ==================================================
# MAIN FUNCTION
# ==================================================

def mask_text(text, settings=None):

    if not text:
        return ""

    if settings is None:
        settings = load_config()

    max_len = settings.get("max_text_length", 200000)
    if len(text) > max_len:
        text = text[:max_len]

    # 1. FIRST: private keys (highest priority)
    text = mask_private_keys(text)

    # 2. collect detections
    findings = collect_findings(text, settings)

    # 3. build spans
    spans = build_spans(text, findings)

    # 4. merge overlaps
    spans = merge_spans(spans)

    # 5. apply final mask
    return apply_mask(text, spans)