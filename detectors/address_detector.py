import re


# ==================================================
# IGNORE WORDS
# ==================================================

IGNORE_WORDS = {
    "телефон",
    "компания",
    "организация",
    "адрес",
    "фио",
    "ооо",
    "ао",
    "пао",
    "зао",
    "ип"
}


# ==================================================
# PATTERNS
# ==================================================

ADDRESS_PATTERNS = [
    r"""
    (?:
        (?:г\.?|город)\s*
        [А-ЯЁ][а-яё-]+,\s*
    )?
    (?:
        ул\.?|улица|проспект|пр-т|бульвар|бул\.|переулок|пер\.|проезд|площадь|набережная|наб\.
    )
    \s+
    [А-ЯЁ][а-яё-]+
    (?:\s+[А-ЯЁ][а-яё-]+)?
    (?:,\s*(?:д\.?|дом)\s*\d+[а-яА-Я]?)?
    (?:,\s*(?:к\.?|корп\.?|корпус)\s*\d+)?
    (?:,\s*(?:стр\.?|строение)\s*\d+)?
    (?:,\s*(?:кв\.?|квартира)\s*\d+)?
    """,

    r"""
    (?:г\.?|город)\s*[А-ЯЁ][а-яё-]+
    """
]


# ==================================================
# CONFIDENCE
# ==================================================

def address_confidence(value):

    score = 0.7

    if "ул" in value or "улица" in value:
        score += 0.1

    if "д" in value:
        score += 0.1

    if "кв" in value or "квартира" in value:
        score += 0.05

    if re.search(r"\d", value):
        score += 0.05

    return min(score, 1.0)


# ==================================================
# CLEAN
# ==================================================

def clean_address(value):

    value = re.sub(r"\s+", " ", value.strip())
    return value


# ==================================================
# VALIDATION
# ==================================================

def is_valid_address(value):

    if len(value) < 6:
        return False

    if value.lower() in IGNORE_WORDS:
        return False

    return True


# ==================================================
# FIND ADDRESSES
# ==================================================

def find_addresses(text):

    results = []

    for pattern in ADDRESS_PATTERNS:

        matches = re.findall(pattern, text, flags=re.VERBOSE)

        for m in matches:

            if isinstance(m, tuple):
                m = "".join(m)

            m = clean_address(m)

            if not is_valid_address(m):
                continue

            results.append({
                "value": m,
                "confidence": address_confidence(m)
            })


    # ==================================================
    # DEDUPLICATION
    # ==================================================

    unique = []
    seen = set()

    for item in results:

        key = item["value"].lower()

        if key in seen:
            continue

        seen.add(key)
        unique.append(item)


    return unique