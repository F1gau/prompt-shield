#!/usr/bin/env python3
"""
Инструмент ПРОДАВЦА для генерации лицензионных ключей. Не поставляется
клиенту как часть работающего приложения — используйте отдельно, у себя.

Примеры:
    python3 scripts/generate_license.py --org "ООО Ромашка" --seats 25 --days 30
    python3 scripts/generate_license.py --org "ООО Ромашка" --seats 25 --months 6
    python3 scripts/generate_license.py --org "ООО Ромашка" --seats 25 --years 1
    python3 scripts/generate_license.py --org "ООО Ромашка" --seats 25 --lifetime
"""

import sys
import os
import csv
import argparse
from datetime import date, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.license import generate_license_key, is_using_demo_secret  # noqa: E402


# Локальный журнал выданных ключей — только у вас (продавца), не
# поставляется клиенту. Так вы не теряете историю: кому, когда,
# на какой срок был выдан ключ, даже если сами не ведёте таблицу.
ISSUED_LOG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "issued_licenses.csv")


def _add_months(d: date, months: int) -> date:

    month_index = d.month - 1 + months
    year = d.year + month_index // 12
    month = month_index % 12 + 1
    day = min(d.day, [31, 29 if year % 4 == 0 and (year % 100 != 0 or year % 400 == 0) else 28,
                      31, 30, 31, 30, 31, 31, 30, 31, 30, 31][month - 1])

    return date(year, month, day)


def _record_issued(org, seats, issued, expires, key):

    is_new = not os.path.exists(ISSUED_LOG)

    with open(ISSUED_LOG, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)

        if is_new:
            writer.writerow(["issued_at", "organization", "seats", "expires", "key"])

        writer.writerow([issued, org, seats, expires or "бессрочно", key])


def main():

    parser = argparse.ArgumentParser(description="Генератор лицензионных ключей Промпт-Щит")
    parser.add_argument("--org", required=True, help="Название организации-клиента")
    parser.add_argument("--seats", type=int, default=1, help="Число рабочих мест")

    duration = parser.add_mutually_exclusive_group(required=True)
    duration.add_argument("--days", type=int, help="Срок действия, дней")
    duration.add_argument("--months", type=int, help="Срок действия, месяцев")
    duration.add_argument("--years", type=float, help="Срок действия, лет")
    duration.add_argument("--lifetime", action="store_true", help="Бессрочная лицензия")

    args = parser.parse_args()

    today = date.today()
    expires = None

    if args.days is not None:
        expires = today + timedelta(days=args.days)
    elif args.months is not None:
        expires = _add_months(today, args.months)
    elif args.years is not None:
        expires = _add_months(today, round(args.years * 12))
    # args.lifetime -> expires остаётся None (бессрочно)

    payload = {
        "org": args.org,
        "seats": args.seats,
        "issued": today.isoformat(),
        "expires": expires.isoformat() if expires else None
    }

    key = generate_license_key(payload)

    _record_issued(args.org, args.seats, today.isoformat(), payload["expires"], key)

    print("\nЛицензионный ключ:\n")
    print(key)
    print(f"\nОрганизация: {args.org}")
    print(f"Мест: {args.seats}")
    print(f"Действует до: {expires.isoformat() if expires else 'бессрочно'}\n")
    print(f"Запись добавлена в {ISSUED_LOG}")
    if is_using_demo_secret():
        print("\nВНИМАНИЕ: ключ подписан ДЕМО-секретом (он публичный).")
        print("Для реального использования задайте PROMPTSHIELD_LICENSE_SECRET")
        print("(одинаковый у генератора и у приложения клиента).\n")


if __name__ == "__main__":
    main()
