import re

from core.checksums import luhn_valid


# ==================================================
# PATTERNS
# ==================================================

BIK_PATTERN = r"\b04\d{7}\b"
ACCOUNT_PATTERN = r"\b\d{20}\b"

# 13-19 цифр, допускаются пробелы/дефисы группами по 4 (типичное
# оформление номера карты человеком) — а не только «слитные» 16 цифр.
CARD_PATTERN = re.compile(r"\b(?:\d[ -]?){13,19}\b")


# ==================================================
# CONFIDENCE HELPERS
# ==================================================

def bik_confidence(value, context):

    score = 0.8

    if "бик" in context or "банк" in context:
        score += 0.1

    if re.match(r"^04\d{7}$", value):
        score += 0.1

    return min(score, 1.0)


def account_confidence(value, context, kind="ACCOUNT"):

    score = 0.8

    if kind == "CORRESPONDENT_ACCOUNT":
        score += 0.05

    if any(x in context for x in ["р/с", "рс", "расчетный", "расчётный"]):
        score += 0.1

    if any(x in context for x in ["к/с", "корреспондент", "корр."]):
        score += 0.1

    return min(score, 1.0)


# ==================================================
# CARD NUMBER DETECTOR (алгоритм Луна)
#
# Номера карт (13-19 цифр) сами по себе неотличимы от случайных
# чисел без проверки контрольной суммы — алгоритм Луна отсекает
# практически все случайные последовательности (~9 из 10 случайных
# чисел не проходят проверку), поэтому найденные без контекста
# совпадения всё равно оставляем, но с более низкой уверенностью.
# ==================================================

CARD_CONTEXT = {"карта", "карты", "card", "visa", "mastercard", "мир", "мaestro"}


def find_cards(text):

    results = []

    for m in CARD_PATTERN.finditer(text):

        raw = m.group(0)
        digits = re.sub(r"[ \-]", "", raw)

        if len(digits) < 13 or len(digits) > 19:
            continue

        if not luhn_valid(digits):
            continue

        start = max(0, m.start() - 40)
        context = text[start:m.start() + 40].lower()

        has_context = any(k in context for k in CARD_CONTEXT)

        results.append({
            "value": digits,
            "confidence": 0.95 if has_context else 0.75
        })

    # dedup
    seen = {}
    for r in results:
        seen[r["value"]] = r

    return list(seen.values())


# ==================================================
# HELPERS
# ==================================================

def unique(values):

    seen = set()
    result = []

    for v in values:
        if v in seen:
            continue
        seen.add(v)
        result.append(v)

    return result


def get_lines(text):

    return [
        line.strip().lower()
        for line in text.splitlines()
        if line.strip()
    ]


# ==================================================
# BIK DETECTOR
# ==================================================

def find_bik(text):

    results = []

    lines = get_lines(text)

    for i, line in enumerate(lines):

        matches = re.findall(BIK_PATTERN, line)

        if not matches:
            continue

        context = line

        if i > 0:
            context += " " + lines[i - 1]

        if "бик" not in context and "банк" not in context:
            continue

        for m in matches:

            results.append({
                "value": m,
                "confidence": bik_confidence(m, context)
            })

    # dedup
    unique_map = {}
    for r in results:
        unique_map[r["value"]] = r

    return list(unique_map.values())


# ==================================================
# ACCOUNT DETECTOR
# ==================================================

def find_accounts(text):

    accounts = []
    corr_accounts = []

    lines = get_lines(text)

    for i, line in enumerate(lines):

        numbers = re.findall(ACCOUNT_PATTERN, line)

        if not numbers:
            continue

        context = line

        if i > 0:
            context += " " + lines[i - 1]

        # --------------------------
        # CORRESPONDENT
        # --------------------------

        if any(x in context for x in ["к/с", "к.с", "кс", "корреспондент", "корр."]):

            for n in numbers:
                corr_accounts.append({
                    "value": n,
                    "confidence": account_confidence(n, context, "CORRESPONDENT_ACCOUNT")
                })

            continue

        # --------------------------
        # REGULAR ACCOUNT
        # --------------------------

        if any(x in context for x in ["р/с", "рс", "расчетный", "расчётный", "расчет", "расчёт"]):

            for n in numbers:
                accounts.append({
                    "value": n,
                    "confidence": account_confidence(n, context, "ACCOUNT")
                })

            continue

    # dedup
    def dedup(lst):
        seen = {}
        for x in lst:
            seen[x["value"]] = x
        return list(seen.values())

    return dedup(accounts), dedup(corr_accounts)


# ==================================================
# MAIN
# ==================================================

def find_bank_details(text):

    findings = []

    # --------------------------
    # BIK
    # --------------------------

    biks = find_bik(text)

    if biks:
        findings.append({
            "type": "BIK",
            "count": len(biks),
            "items": biks
        })

    # --------------------------
    # ACCOUNTS
    # --------------------------

    accounts, corr = find_accounts(text)

    if accounts:
        findings.append({
            "type": "ACCOUNT",
            "count": len(accounts),
            "items": accounts
        })

    if corr:
        findings.append({
            "type": "CORRESPONDENT_ACCOUNT",
            "count": len(corr),
            "items": corr
        })

    # --------------------------
    # CARD NUMBERS
    # --------------------------

    cards = find_cards(text)

    if cards:
        findings.append({
            "type": "CARD_NUMBER",
            "count": len(cards),
            "items": cards
        })

    return findings