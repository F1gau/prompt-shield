import re

from core.checksums import is_valid_inn_org, is_valid_ogrn


# ==================================================
# ИЗВЕСТНЫЕ ЛИЧНЫЕ (НЕ КОРПОРАТИВНЫЕ) ПОЧТОВЫЕ ДОМЕНЫ
#
# Без этого списка личный email вида ivan@gmail.com помечался как
# "корпоративная почта" — что сбивает с толку в отчёте и раздувает
# оценку риска.
# ==================================================

PERSONAL_EMAIL_DOMAINS = {
    "gmail.com", "mail.ru", "yandex.ru", "yandex.com", "ya.ru",
    "outlook.com", "hotmail.com", "rambler.ru", "bk.ru", "list.ru",
    "inbox.ru", "icloud.com", "live.com", "yahoo.com", "protonmail.com",
    "gmx.com", "aol.com", "mailfence.com"
}


# ==================================================
# CONFIDENCE HELPERS
# ==================================================

def org_confidence(name: str) -> float:
    score = 0.85

    if not name:
        return 0.0

    name = name.strip()

    if name.startswith(("ООО", "ПАО", "АО", "ЗАО")):
        score += 0.1

    if len(name) > 5:
        score += 0.05

    return round(min(score, 1.0), 3)


def numeric_confidence(value, expected_len, checksum_ok=None):
    """
    Если контрольная сумма подтверждена — высокая уверенность.
    Если сумма НЕ прошла проверку — это, скорее всего, случайное
    число, а не настоящий ИНН/ОГРН, поэтому уверенность резко ниже
    (совпадение остаётся видимым, но явно помечено как менее надёжное).
    """

    value = re.sub(r"\D", "", str(value))

    if checksum_ok is True:
        return 0.98

    if checksum_ok is False:
        return 0.35

    if len(value) == expected_len:
        return 0.95

    return 0.6


# ==================================================
# ORGANIZATION
# ==================================================

def find_organizations(text):

    pattern = r"(ООО|ПАО|АО|ЗАО)\s+[\"«»]?\s*([A-Яа-яA-Za-z0-9\- ]{2,80})"

    matches = re.findall(pattern, text)

    results = []
    seen = set()

    for form, name in matches:

        full = f"{form} {name}".strip()
        full = re.sub(r"\s+", " ", full)

        if full.lower() in seen:
            continue

        seen.add(full.lower())

        results.append({
            "value": full,
            "confidence": org_confidence(full)
        })

    return results


# ==================================================
# INN ORG (с проверкой контрольной суммы)
# ==================================================

def find_org_inn(text):

    pattern = r"\bИНН\s*:?\s*(\d{10})\b"
    values = set(re.findall(pattern, text))

    return [
        {
            "value": v,
            "confidence": numeric_confidence(v, 10, is_valid_inn_org(v))
        }
        for v in values
    ]


# ==================================================
# KPP
# ==================================================

def find_kpp(text):

    pattern = r"\bКПП\s*:?\s*(\d{9})\b"
    values = re.findall(pattern, text)

    return [
        {
            "value": v,
            "confidence": numeric_confidence(v, 9)
        }
        for v in set(values)
    ]


# ==================================================
# OGRN (с проверкой контрольной суммы)
# ==================================================

def find_ogrn(text):

    pattern = r"\bОГРН(?:ИП)?\s*:?\s*(\d{13,15})\b"
    values = set(re.findall(pattern, text))

    return [
        {
            "value": v,
            "confidence": numeric_confidence(v, 13, is_valid_ogrn(v))
        }
        for v in values
    ]


# ==================================================
# CORPORATE EMAIL
#
# Помечаем как «корпоративную» почту только если домен НЕ входит в
# список известных личных почтовых сервисов — иначе личный email
# ошибочно попадает в реквизиты организации.
# ==================================================

def find_corporate_emails(text):

    pattern = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"

    emails = set(re.findall(pattern, text))

    results = []

    for e in emails:

        domain = e.rsplit("@", 1)[-1].lower()

        if domain in PERSONAL_EMAIL_DOMAINS:
            continue

        results.append({
            "value": e,
            "confidence": 0.9
        })

    return results


# ==================================================
# MAIN FUNCTION
# ==================================================

def find_company_details(text):

    findings = []

    orgs = find_organizations(text)
    if orgs:
        findings.append({
            "type": "ОРГАНИЗАЦИЯ",
            "count": len(orgs),
            "items": orgs
        })

    inn = find_org_inn(text)
    if inn:
        findings.append({
            "type": "INN_ORG",
            "count": len(inn),
            "items": inn
        })

    kpp = find_kpp(text)
    if kpp:
        findings.append({
            "type": "KPP",
            "count": len(kpp),
            "items": kpp
        })

    ogrn = find_ogrn(text)
    if ogrn:
        findings.append({
            "type": "OGRN",
            "count": len(ogrn),
            "items": ogrn
        })

    emails = find_corporate_emails(text)
    if emails:
        findings.append({
            "type": "CORPORATE_EMAIL",
            "count": len(emails),
            "items": emails
        })

    return findings
