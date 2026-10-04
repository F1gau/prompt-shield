import re
from datetime import datetime

from core.checksums import is_valid_snils, is_valid_inn_person


# ==================================================
# UTIL
# ==================================================

def unique_dicts(items):
    """Дедупликация списка {'value':..,'confidence':..} по значению."""

    seen = set()
    result = []

    for item in items:

        v = item["value"]

        if v in seen:
            continue

        seen.add(v)
        result.append(item)

    return result


def _context_has(text, pos, keywords, window=40):

    start = max(0, pos - window)
    fragment = text[start:pos + window].lower()

    return any(k in fragment for k in keywords)


# ==================================================
# PHONE
# ==================================================

PHONE_PATTERN = re.compile(r"""
    (?<!\d)
    (?:\+7|8)
    [\s\-]?
    \(?
    \d{3}
    \)?
    [\s\-]?
    \d{3}
    [\s\-]?
    \d{2}
    [\s\-]?
    \d{2}
    (?!\d)
""", re.VERBOSE)


def find_phones(text):

    results = []

    for m in PHONE_PATTERN.finditer(text):

        value = m.group(0).strip()

        results.append({"value": value, "confidence": 0.92})

    return unique_dicts(results)


# ==================================================
# EMAIL
# ==================================================

EMAIL_PATTERN = re.compile(r"""
    \b
    [A-Za-z0-9._%+-]+
    @
    [A-Za-z0-9.-]+
    \.
    [A-Za-z]{2,}
    \b
""", re.VERBOSE)


def find_emails(text):

    results = [
        {"value": m.group(0), "confidence": 0.97}
        for m in EMAIL_PATTERN.finditer(text)
    ]

    return unique_dicts(results)


# ==================================================
# PASSPORT
#
# У серии+номера паспорта РФ нет контрольной суммы — это просто
# порядковый номер. Поэтому валидировать чек-суммой нечего, но можно
# резко снизить долю случайных совпадений через контекст: если рядом
# по тексту встречается слово «паспорт» — уверенность высокая,
# если нет — запись всё равно показывается, но с более низкой
# уверенностью (это могут быть и произвольные 10-значные коды).
# ==================================================

PASSPORT_PATTERN = re.compile(r"(?<!\d)\d{4}\s\d{6}(?!\d)")

PASSPORT_CONTEXT = {"паспорт", "серия", "выдан", "паспортные данные"}


def find_passports(text):

    results = []

    for m in PASSPORT_PATTERN.finditer(text):

        value = m.group(0)
        has_context = _context_has(text, m.start(), PASSPORT_CONTEXT)

        results.append({
            "value": value,
            "confidence": 0.95 if has_context else 0.55
        })

    return unique_dicts(results)


# ==================================================
# SNILS
#
# check_snils() в предыдущей версии файла существовал, но не
# вызывался вообще — регэксп-совпадения принимались без проверки
# контрольного числа. Теперь контрольная сумма реально используется.
# ==================================================

SNILS_PATTERN = re.compile(r"(?<!\d)\d{3}[-\s]\d{3}[-\s]\d{3}\s?\d{2}(?!\d)")


def find_snils(text):

    results = []

    for m in SNILS_PATTERN.finditer(text):

        value = m.group(0)
        valid = is_valid_snils(value)

        results.append({
            "value": value,
            "confidence": 0.97 if valid else 0.3
        })

    return unique_dicts(results)


# ==================================================
# BIRTH DATE
# ==================================================

BIRTH_DATE_PATTERN = re.compile(r"""
    (?<!\d)
    (0[1-9]|[12]\d|3[01])
    \.
    (0[1-9]|1[0-2])
    \.
    (19\d{2}|20\d{2})
    (?!\d)
""", re.VERBOSE)


def find_birth_dates(text):

    results = []

    for m in BIRTH_DATE_PATTERN.finditer(text):

        value = ".".join(m.groups())

        try:
            datetime.strptime(value, "%d.%m.%Y")
        except ValueError:
            continue

        has_context = _context_has(text, m.start(), {"дата рождения", "родился", "родилась", "рождения", "г.р.", "др:"})

        results.append({
            "value": value,
            "confidence": 0.9 if has_context else 0.6
        })

    return unique_dicts(results)


# ==================================================
# INN PERSON (контрольная сумма уже была и остаётся обязательной —
# случайное 12-значное число почти никогда её не проходит)
# ==================================================

INN_PERSON_PATTERN = re.compile(r"\b\d{12}\b")


def find_person_inn(text):

    results = []

    for m in INN_PERSON_PATTERN.finditer(text):

        value = m.group(0)

        if is_valid_inn_person(value):
            results.append({"value": value, "confidence": 0.98})

    return unique_dicts(results)


# ==================================================
# FIO
#
# Три капитализированных кириллических слова подряд — довольно грубый
# сигнал (может случайно сработать на начале предложения, названии
# улицы и т.п.), поэтому уверенность по умолчанию не максимальная.
# ==================================================

FIO_PATTERN = re.compile(r"""
    \b
    [А-ЯЁ][а-яё]{2,}
    [\ \t]
    [А-ЯЁ][а-яё]{2,}
    [\ \t]
    [А-ЯЁ][а-яё]{2,}
    \b
""", re.VERBOSE)
# Разделитель — только пробел/табуляция, а не \s: иначе «Иван Иванов\nТелефон»
# (конец строки + заголовок следующей) принимался за ФИО из трёх слов.

FIO_BLACKLIST = {"ООО", "ПАО", "АО", "Компания", "Банк"}

FIO_CONTEXT = {"фио", "имя", "клиент", "сотрудник", "директор", "подписал", "контакт"}


def find_persons(text):

    results = []

    for m in FIO_PATTERN.finditer(text):

        value = m.group(0)

        if any(b in value for b in FIO_BLACKLIST):
            continue

        has_context = _context_has(text, m.start(), FIO_CONTEXT, window=60)

        results.append({
            "value": value,
            "confidence": 0.9 if has_context else 0.75
        })

    return unique_dicts(results)


# ==================================================
# MAIN
# ==================================================

def find_personal_data(text):

    findings = []

    detectors = [
        ("ФИО", find_persons),
        ("PHONE", find_phones),
        ("EMAIL", find_emails),
        ("PASSPORT", find_passports),
        ("SNILS", find_snils),
        ("BIRTH_DATE", find_birth_dates),
        ("INN_PERSON", find_person_inn)
    ]

    for name, detector in detectors:

        values = detector(text)

        if not values:
            continue

        findings.append({
            "type": name,
            "count": len(values),
            "items": values
        })

    return findings
