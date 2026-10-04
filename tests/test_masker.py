from core.config import load_config
from core.masker import mask_text


def test_empty_text():
    assert mask_text("") == ""


def test_plain_text_is_unchanged():
    text = "Расскажи, как работает кэширование в браузере."
    assert mask_text(text) == text


def test_original_values_are_removed():
    text = (
        "Контактное лицо: Иванов Иван Иванович\n"
        "Телефон: +7 912 345 67 89\n"
        "Почта: ivan.petrov@gmail.com\n"
        "Паспорт: 4510 123456\n"
        "API key: sk_live_abcdef1234567890abcdef1234567890\n"
        "password = Sup3rS3cret!\n"
    )

    masked = mask_text(text)

    for secret in ("Иванов Иван Иванович", "912 345 67 89", "ivan.petrov@gmail.com",
                   "4510 123456", "sk_live_abcdef1234567890abcdef1234567890", "Sup3rS3cret!"):
        assert secret not in masked

    for placeholder in ("[ФИО]", "[ТЕЛЕФОН]", "[EMAIL]", "[ПАСПОРТ]", "[API_KEY]", "[PASSWORD]"):
        assert placeholder in masked


def test_labels_and_structure_are_preserved():
    masked = mask_text("Телефон: +7 912 345 67 89\nГород: Тверь")
    assert masked.startswith("Телефон: [ТЕЛЕФОН]")
    assert "Город: Тверь" in masked


def test_organization_in_quotes_is_masked():
    masked = mask_text('Договор с ООО "Ромашка" заключён')
    assert "Ромашка" not in masked
    assert "[ОРГАНИЗАЦИЯ]" in masked


def test_card_with_spaces_is_masked():
    masked = mask_text("Карта 4111 1111 1111 1111, срок 12/30")
    assert "4111" not in masked
    assert "[НОМЕР_КАРТЫ]" in masked


def test_private_key_block_is_masked():
    key = "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy\n-----END RSA PRIVATE KEY-----"
    masked = mask_text(f"вот ключ:\n{key}\nспасибо")
    assert "MIIBOgIBAAJ" not in masked
    assert "[PRIVATE_KEY]" in masked


def test_disabled_detector_is_not_applied():
    settings = load_config()
    settings["detectors"]["personal"] = False

    masked = mask_text("Почта: ivan.petrov@gmail.com", settings)

    assert "ivan.petrov@gmail.com" in masked


def test_text_is_truncated_to_max_length():
    settings = load_config()
    settings["max_text_length"] = 10

    assert len(mask_text("а" * 100, settings)) <= 10
