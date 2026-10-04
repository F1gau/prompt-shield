from collections import defaultdict


# ==================================================
# SAFE UTILS
# ==================================================

def safe_get(items):
    if not items:
        return []
    return items if isinstance(items, list) else [items]


def normalize(values):
    seen = set()
    result = []

    for v in values:

        if not v:
            continue

        # findings items приходят в виде {"value": ..., "confidence": ...}
        if isinstance(v, dict):
            v = v.get("value")

        if not v:
            continue

        v = str(v).strip()

        if v not in seen:
            seen.add(v)
            result.append(v)

    return result


# ==================================================
# ENTITY STATE
# ==================================================

def build_entities(findings):

    companies = {}
    persons = {}
    banks = {}


    # =========================
    # HELPERS
    # =========================

    def get_company():
        if "main" not in companies:
            companies["main"] = {
                "type": "COMPANY",
                "name": None,
                "attributes": defaultdict(list)
            }
        return companies["main"]


    def get_person():
        if "main" not in persons:
            persons["main"] = {
                "type": "PERSON",
                "name": None,
                "attributes": defaultdict(list)
            }
        return persons["main"]


    def get_bank():
        if "main" not in banks:
            banks["main"] = {
                "type": "BANK",
                "name": None,
                "attributes": defaultdict(list)
            }
        return banks["main"]


    # =================================================
    # PROCESS FINDINGS
    # =================================================

    for item in findings:

        t = item.get("type")
        values = normalize(safe_get(item.get("items")))


        # -------------------------
        # COMPANY
        # -------------------------

        if t == "ОРГАНИЗАЦИЯ":
            c = get_company()
            if values:
                c["name"] = values[0]

        elif t in ["INN_ORG", "KPP", "OGRN", "CORPORATE_EMAIL"]:
            c = get_company()
            c["attributes"][t].extend(values)


        # -------------------------
        # PERSON
        # -------------------------

        elif t == "ФИО":
            p = get_person()
            if values:
                p["name"] = values[0]

        elif t in ["INN_PERSON", "BIRTH_DATE", "PHONE", "EMAIL"]:
            p = get_person()
            p["attributes"][t].extend(values)


        # -------------------------
        # BANK
        # -------------------------

        elif t in ["BIK", "ACCOUNT", "CORRESPONDENT_ACCOUNT", "CARD_NUMBER"]:
            b = get_bank()
            b["attributes"][t].extend(values)


    # =================================================
    # FINAL CLEAN
    # =================================================

    def finalize(entity):
        if not entity:
            return []

        entity["attributes"] = {
            k: normalize(v)
            for k, v in entity["attributes"].items()
            if v
        }

        return [entity]


    return {
        "COMPANIES": finalize(companies.get("main")),
        "PERSONS": finalize(persons.get("main")),
        "BANKS": finalize(banks.get("main"))
    }