import re

"""
Детектор попыток prompt injection / jailbreak.

В отличие от остальных детекторов, здесь ищутся не персональные или
финансовые данные, а ПОПЫТКИ МАНИПУЛЯЦИИ поведением AI-модели —
инструкции, которые пользователь пытается "подсунуть" модели поверх
системного промпта. Это отдельная категория угроз (Prompt Security),
и по смыслу она весомее большинства утечек данных: если атака сработает,
модель может сама раскрыть куда больше, чем было в исходном запросе.
"""


# Каждый шаблон — (регулярное выражение, человекочитаемое описание).
# Шаблоны сознательно широкие (лучше лишний раз показать пользователю
# найденное совпадение для проверки, чем пропустить попытку атаки).
INJECTION_PATTERNS = [
    (r"игнорируй\s+(все\s+)?(предыдущие|прошлые|вышеуказанные)\s+(инструкции|указания|правила)",
     "Попытка отменить предыдущие инструкции"),

    (r"забудь\s+(все\s+)?(инструкции|правила|контекст)",
     "Попытка заставить модель забыть контекст/правила"),

    (r"(покажи|раскрой|выведи)\s+(мне\s+)?(свой\s+)?(системный\s+промпт|system\s*prompt|системные\s+инструкции|скрытые\s+настройки)",
     "Попытка получить системный промпт"),

    (r"расскажи\s+(мне\s+)?(внутренние|секретные|служебные)\s+(данные|инструкции|настройки)",
     "Попытка получить служебную информацию модели"),

    (r"ignore\s+(all\s+|any\s+)?(previous|prior|above)\s+instructions",
     "Attempt to override previous instructions (EN)"),

    (r"disregard\s+(all\s+|any\s+)?(previous|prior)\s+(instructions|rules)",
     "Attempt to disregard prior instructions (EN)"),

    (r"reveal\s+(your\s+|the\s+)?(system\s*prompt|hidden\s+instructions|internal\s+configuration)",
     "Attempt to reveal system prompt (EN)"),

    (r"you\s+are\s+now\s+(DAN|in\s+developer\s+mode|unrestricted|jailbroken)",
     "Классический jailbreak-шаблон (DAN / developer mode)"),

    (r"(включи|активируй|переведи\s+(меня|тебя)\s+в)\s+режим\s+разработчика",
     "Попытка активировать 'режим разработчика'"),

    (r"pretend\s+(that\s+)?you\s+(are|have)\s+no\s+(restrictions|rules|guidelines)",
     "Попытка снять ограничения через ролевую игру (EN)"),

    (r"bypass\s+(your\s+|all\s+|the\s+)?(restrictions|filters|safety\s+rules|guidelines)",
     "Попытка обойти ограничения безопасности (EN)"),

    (r"act\s+as\s+(if\s+you\s+(are|were)\s+)?(an?\s+)?(unfiltered|uncensored|jailbroken)\s+AI",
     "Попытка ролевой атаки на ограничения модели (EN)"),

    (r"выведи\s+(весь\s+)?(твой\s+|свой\s+)?(исходный\s+код|промпт\s+целиком)",
     "Попытка извлечь исходный промпт целиком"),
]

_COMPILED = [(re.compile(pattern, re.IGNORECASE), label) for pattern, label in INJECTION_PATTERNS]


def find_prompt_injections(text):

    if not text:
        return []

    matches = []
    seen_spans = set()

    for pattern, label in _COMPILED:

        for m in pattern.finditer(text):

            span = (m.start(), m.end())

            if span in seen_spans:
                continue

            seen_spans.add(span)

            matches.append({
                "value": f"{label}: «{m.group(0).strip()}»",
                "confidence": 0.9
            })

    if not matches:
        return []

    return [{
        "type": "PROMPT_INJECTION",
        "count": len(matches),
        "items": matches
    }]
