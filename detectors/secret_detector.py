import re


# ==================================================
# PATTERNS
# ==================================================

PATTERNS = {

    "API_KEY":
        r"(?i)\b(?:api[_\- ]?key|apikey)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{16,})['\"]?",


    "SECRET_KEY":
        r"(?i)\b(?:secret[_\- ]?key|secret)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{16,})['\"]?",


    "ACCESS_TOKEN":
        r"(?i)\b(?:access[_\- ]?token|access_token)\s*[:=]\s*['\"]?([A-Za-z0-9_\-\.]{20,})['\"]?",


    "TOKEN":
        r"(?i)\btoken\s*[:=]\s*['\"]?([A-Za-z0-9_\-\.]{20,})['\"]?",


    "BEARER_TOKEN":
        r"(?i)\bBearer\s+([A-Za-z0-9_\-\.]+)",


    "JWT_TOKEN":
        r"\b(eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)\b",


    "GITHUB_TOKEN":
        r"\b(gh[pousr]_[A-Za-z0-9]{20,})\b",


    "TELEGRAM_TOKEN":
        r"\b(\d{8,12}:[A-Za-z0-9_-]{30,})\b",


    "AWS_KEY":
        r"\b(AKIA[0-9A-Z]{16})\b",


    # PRIVATE KEY BLOCK (FULL FIX)
    "PRIVATE_KEY":
        r"(-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----)",


    "PASSWORD":
        r"(?i)\b(?:password|passwd|pwd|пароль)\s*[:=]\s*['\"]?([^\s'\"]{4,})",


    "CREDENTIALS":
        r"(?i)\b(?:username|user|login|логин)\s*[:=]\s*['\"]?([A-Za-z0-9_.@\-]+)",


    "IP":
        r"\b((?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
        r"(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})\b"

}


# ==================================================
# HELPERS
# ==================================================

def normalize(v):
    return v.strip().replace("\r", "").replace("\n", " ")


def unique(values):
    seen = set()
    result = []

    for v in values:
        v = normalize(v)

        if v not in seen:
            seen.add(v)
            result.append(v)

    return result


# ==================================================
# CONFIDENCE (simple heuristic layer)
# ==================================================

def confidence(type_name, value):

    base = 0.8

    if type_name in {"JWT_TOKEN", "BEARER_TOKEN"}:
        if len(value) > 40:
            base = 0.95

    if type_name == "PRIVATE_KEY":
        base = 0.99

    if type_name == "PASSWORD":
        if len(value) < 8:
            base = 0.6

    return min(base, 1.0)


# ==================================================
# DETECTOR
# ==================================================

def find_secrets(text):

    findings = []

    for name, pattern in PATTERNS.items():

        matches = re.findall(pattern, text, flags=re.IGNORECASE | re.MULTILINE)

        if not matches:
            continue

        cleaned = unique(matches)

        findings.append({
            "type": name,
            "count": len(cleaned),
            "items": cleaned,
            "confidence": round(
                sum(confidence(name, v) for v in cleaned) / len(cleaned),
                3
            )
        })

    return findings