"""
Механизм принятия решения (ALLOW / MASK / BLOCK).

По сути — явная маркировка того, что и так следует из уровня риска,
но в терминах, привычных для описания политик защиты запросов к LLM. Дополнительно
учитывает самодекларируемый AI-сервис: если пользователь указал сервис,
который администратор пометил как запрещённый, решение эскалируется до
BLOCK независимо от содержимого текста.

Важно: BLOCK здесь — это РЕКОМЕНДАЦИЯ пользователю не отправлять текст,
а не техническое блокирование передачи (проверка не встроена в канал
до AI-сервиса, она отдельный шаг перед копированием текста).
"""

RISK_TO_ACTION = {
    "Низкий": "ALLOW",
    "Средний": "MASK",
    "Высокий": "BLOCK",
    "Критический": "BLOCK"
}

ACTION_LABELS = {
    "ALLOW": "Разрешить",
    "MASK": "Маскировать перед отправкой",
    "BLOCK": "Не отправлять"
}


def recommend_action(risk, provider_blocked=False):

    if provider_blocked:
        return "BLOCK"

    return RISK_TO_ACTION.get(risk, "MASK")


def action_label(action):
    return ACTION_LABELS.get(action, action)


def is_provider_blocked(settings, destination):
    """
    destination — ключ провайдера (chatgpt/gigachat/yandexgpt/claude/
    local_llm/other) или None, если пользователь не указал. Без
    указания сервиса решение принимается только по содержимому текста.
    """

    if not destination:
        return False

    providers = settings.get("ai_providers", {})
    provider = providers.get(destination)

    if not provider:
        return False

    return not provider.get("allowed", True)
