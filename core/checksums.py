"""
Проверка контрольных сумм официальных российских идентификаторов.

Регулярное выражение вида «10 цифр подряд» само по себе ничего не
подтверждает — это может быть случайный номер счёта, артикул или
телефон без кода страны. Контрольная сумма резко снижает долю
ложных срабатываний, отсекая случайные числа, которые «похожи» на
ИНН/ОГРН/СНИЛС, но не проходят официальный алгоритм проверки.
"""


# ==================================================
# ИНН ЮРИДИЧЕСКОГО ЛИЦА (10 цифр)
# ==================================================

def is_valid_inn_org(value):

    digits = _digits_only(value)

    if len(digits) != 10:
        return False

    weights = [2, 4, 10, 3, 5, 9, 4, 6, 8]

    n = sum(int(d) * w for d, w in zip(digits[:9], weights)) % 11 % 10

    return n == int(digits[9])


# ==================================================
# ИНН ФИЗИЧЕСКОГО ЛИЦА / ИП (12 цифр)
# ==================================================

def is_valid_inn_person(value):

    digits = _digits_only(value)

    if len(digits) != 12:
        return False

    d = list(map(int, digits))

    n10 = (
        7 * d[0] + 2 * d[1] + 4 * d[2] + 10 * d[3] + 3 * d[4] +
        5 * d[5] + 9 * d[6] + 4 * d[7] + 6 * d[8] + 8 * d[9]
    ) % 11 % 10

    n11 = (
        3 * d[0] + 7 * d[1] + 2 * d[2] + 4 * d[3] + 10 * d[4] +
        3 * d[5] + 5 * d[6] + 9 * d[7] + 4 * d[8] + 6 * d[9] + 8 * d[10]
    ) % 11 % 10

    return d[10] == n10 and d[11] == n11


# ==================================================
# ОГРН (13 цифр) / ОГРНИП (15 цифр)
# ==================================================

def is_valid_ogrn(value):

    digits = _digits_only(value)

    if len(digits) == 13:
        n12 = int(digits[:12])
        check = (n12 % 11) % 10
        return check == int(digits[12])

    if len(digits) == 15:
        n14 = int(digits[:14])
        check = (n14 % 13) % 10
        return check == int(digits[14])

    return False


# ==================================================
# СНИЛС (11 цифр, из них 9 номер + 2 контрольные)
# ==================================================

def is_valid_snils(value):

    digits = _digits_only(value)

    if len(digits) != 11:
        return False

    number = digits[:9]
    control = int(digits[9:11])

    # СНИЛС из одних и тех же/последовательных цифр не выдаётся
    if number in ("000000000",) or len(set(number)) == 1:
        return False

    total = sum(int(d) * (9 - i) for i, d in enumerate(number))

    if total < 100:
        checksum = total
    elif total in (100, 101):
        checksum = 0
    else:
        checksum = total % 101
        if checksum == 100:
            checksum = 0

    return checksum == control


# ==================================================
# НОМЕРА БАНКОВСКИХ КАРТ (алгоритм Луна)
# ==================================================

def luhn_valid(value):

    digits = _digits_only(value)

    if len(digits) not in (13, 14, 15, 16, 17, 18, 19):
        return False

    total = 0
    reverse_digits = digits[::-1]

    for i, d in enumerate(reverse_digits):

        n = int(d)

        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9

        total += n

    return total % 10 == 0


# ==================================================
# HELPERS
# ==================================================

def _digits_only(value):
    return "".join(ch for ch in str(value) if ch.isdigit())
