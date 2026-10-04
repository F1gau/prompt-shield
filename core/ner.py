"""
Опциональный слой распознавания именованных сущностей (NER) для
русского языка на основе библиотеки Natasha.

Регулярные выражения в detectors/personal_detector.py и
company_detector.py требуют строгого формата («Три Слова С Большой
Буквы» для ФИО, «ООО + название» для организаций) и пропускают многое:
имя без отчества, ФИО в косвенном падеже, названия организаций без
организационно-правовой формы и т.п. NER-модель распознаёт такие
сущности по контексту, а не по формату написания.

Требует: pip install natasha
Без установленного пакета модуль тихо возвращает findings без
изменений — регулярные выражения продолжают работать как раньше.
"""

import logging

logger = logging.getLogger("promptshield.ner")

_NATASHA_READY = False
_segmenter = None
_ner_tagger = None

try:
    from natasha import Segmenter, NewsEmbedding, NewsNERTagger, Doc
    _NATASHA_AVAILABLE = True
except ImportError:
    _NATASHA_AVAILABLE = False


def is_available():
    return _NATASHA_AVAILABLE


def _ensure_loaded():
    """Инициализация моделей — тяжёлая операция (~секунды, загрузка
    векторных эмбеддингов), поэтому выполняется один раз и лениво,
    только если NER действительно понадобился."""

    global _NATASHA_READY, _segmenter, _ner_tagger

    if _NATASHA_READY or not _NATASHA_AVAILABLE:
        return

    try:
        _segmenter = Segmenter()
        embedding = NewsEmbedding()
        _ner_tagger = NewsNERTagger(embedding)
        _NATASHA_READY = True
    except Exception:
        logger.exception("Не удалось загрузить модели Natasha — NER-слой отключён")


def _already_covered(findings, item_type, value_lower):

    for item in findings:
        if item.get("type") != item_type:
            continue
        for v in item.get("items", []):
            existing = v.get("value") if isinstance(v, dict) else v
            if existing and str(existing).strip().lower() == value_lower:
                return True
            # частичное совпадение (например, «Иванов» внутри «Иванов Петр Сергеевич»)
            if existing and (value_lower in str(existing).lower() or str(existing).lower() in value_lower):
                return True

    return False


def merge_ner_findings(text, findings, settings=None):
    """
    Дополняет findings сущностями, найденными NER-моделью, если она
    доступна. Не трогает существующие regex-находки — только
    добавляет то, что regex пропустил, с умеренной уверенностью
    (NER статистически надёжен, но менее детерминирован, чем
    проверка контрольной суммы или точный формат).
    """

    if not _NATASHA_AVAILABLE:
        return findings

    # NER — довольно ресурсоёмкая операция; не прогоняем её на очень
    # длинных текстах, чтобы не превращать быструю проверку в долгую
    if len(text) > 50000:
        return findings

    _ensure_loaded()

    if not _NATASHA_READY:
        return findings

    try:
        doc = Doc(text)
        doc.segment(_segmenter)
        doc.tag_ner(_ner_tagger)
    except Exception:
        logger.exception("Ошибка при выполнении NER-разметки")
        return findings

    new_persons = []
    new_orgs = []

    for span in getattr(doc, "spans", []):

        value = span.text.strip()

        if len(value) < 3:
            continue

        value_lower = value.lower()

        if span.type == "PER":
            if not _already_covered(findings, "ФИО", value_lower):
                new_persons.append({"value": value, "confidence": 0.8})

        elif span.type == "ORG":
            if not _already_covered(findings, "ОРГАНИЗАЦИЯ", value_lower):
                new_orgs.append({"value": value, "confidence": 0.75})

    findings = list(findings)

    if new_persons:
        findings.append({"type": "ФИО", "items": new_persons, "count": len(new_persons)})

    if new_orgs:
        findings.append({"type": "ОРГАНИЗАЦИЯ", "items": new_orgs, "count": len(new_orgs)})

    return findings
