import os
from datetime import datetime

from reportlab.lib.colors import HexColor
from reportlab.lib.enums import TA_CENTER, TA_RIGHT
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle
)
from reportlab.lib.units import mm

from core.config import load_config


from core.paths import resource_path, data_path

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FONT_DIR = resource_path("fonts")


# =====================================================
# РЕГИСТРАЦИЯ ШРИФТОВ (один раз)
# =====================================================

_FONTS_REGISTERED = False


def _register_fonts():

    global _FONTS_REGISTERED

    if _FONTS_REGISTERED:
        return

    pdfmetrics.registerFont(
        TTFont("DejaVu", os.path.join(FONT_DIR, "DejaVuSans.ttf"))
    )

    pdfmetrics.registerFont(
        TTFont("DejaVu-Bold", os.path.join(FONT_DIR, "DejaVuSans-Bold.ttf"))
    )

    _FONTS_REGISTERED = True


# =====================================================
# ФУТЕР / НУМЕРАЦИЯ СТРАНИЦ
# =====================================================

def _footer(canvas, doc):

    canvas.saveState()
    canvas.setFont("DejaVu", 8)
    canvas.setFillColor(HexColor("#6b7280"))

    canvas.drawString(
        18 * mm, 10 * mm,
        "Сформировано системой «Промпт-Щит» — конфиденциально"
    )

    canvas.drawRightString(
        doc.pagesize[0] - 18 * mm, 10 * mm,
        f"Стр. {doc.page}"
    )

    canvas.restoreState()


# =====================================================
# ИЗВЛЕЧЕНИЕ ЗНАЧЕНИЯ (fix: items могут быть dict {value, confidence})
# =====================================================

def _value_and_confidence(raw):

    if isinstance(raw, dict):
        return str(raw.get("value", "")), raw.get("confidence")

    return str(raw), None


def _escape(text):

    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


# =====================================================
# PDF
# =====================================================

def generate_report(findings, risk, organization_name=None, analyst_name=None, source_label=None):

    _register_fonts()

    cfg = load_config()

    if not organization_name:
        organization_name = cfg.get("organization_name", "")

    filename = datetime.now().strftime("PromptShield_%Y%m%d_%H%M%S.pdf")
    filepath = data_path("reports", filename)

    doc = SimpleDocTemplate(
        filepath,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm
    )

    styles = getSampleStyleSheet()

    title = styles["Title"]
    title.fontName = "DejaVu-Bold"
    title.alignment = TA_CENTER

    h = styles["Heading2"]
    h.fontName = "DejaVu-Bold"

    normal = styles["BodyText"]
    normal.fontName = "DejaVu"

    small = styles["BodyText"].clone("small")
    small.fontName = "DejaVu"
    small.fontSize = 9
    small.textColor = HexColor("#6b7280")

    story = []

    # =====================================================
    # Заголовок / шапка отчёта
    # =====================================================

    story.append(Paragraph("ПРОМПТ-ЩИТ", title))
    story.append(Paragraph("Отчёт проверки конфиденциальных данных", normal))

    story.append(Spacer(1, 10))

    meta_lines = [
        f"<b>Дата проверки:</b> {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}"
    ]

    if organization_name:
        meta_lines.append(f"<b>Организация:</b> {_escape(organization_name)}")

    if analyst_name:
        meta_lines.append(f"<b>Проверил:</b> {_escape(analyst_name)}")

    if source_label:
        meta_lines.append(f"<b>Источник:</b> {_escape(source_label)}")

    for line in meta_lines:
        story.append(Paragraph(line, normal))

    story.append(Spacer(1, 15))

    # =====================================================
    # Риск
    # =====================================================

    risk_color = {
        "Низкий": "#16a34a",
        "Средний": "#ca8a04",
        "Высокий": "#ea580c",
        "Критический": "#dc2626"
    }.get(risk, "#000000")

    story.append(Paragraph("Уровень риска", h))

    risk_style = styles["Heading1"].clone("risk_style")
    risk_style.fontName = "DejaVu-Bold"
    risk_style.textColor = HexColor(risk_color)

    story.append(Paragraph(_escape(risk), risk_style))

    story.append(Spacer(1, 15))

    # =====================================================
    # Сводная таблица
    # =====================================================

    table_data = [["Тип данных", "Количество"]]
    total = 0

    for item in findings:
        table_data.append([item.get("type", ""), str(item.get("count", 0))])
        total += item.get("count", 0)

    table_data.append(["ВСЕГО", str(total)])

    table = Table(table_data, colWidths=[120 * mm, 40 * mm])

    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), HexColor("#2563eb")),
        ("TEXTCOLOR", (0, 0), (-1, 0), HexColor("#ffffff")),
        ("FONTNAME", (0, 0), (-1, 0), "DejaVu-Bold"),
        ("FONTNAME", (0, 1), (-1, -1), "DejaVu"),
        ("FONTNAME", (0, -1), (-1, -1), "DejaVu-Bold"),
        ("BACKGROUND", (0, -1), (-1, -1), HexColor("#f3f4f6")),
        ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#cccccc")),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
        ("TOPPADDING", (0, 1), (-1, -1), 6),
    ]))

    story.append(table)
    story.append(Spacer(1, 20))

    # =====================================================
    # Подробности (fix: value может быть dict {value, confidence})
    # =====================================================

    story.append(Paragraph("Найденные сущности", h))
    story.append(Spacer(1, 5))

    if not findings:
        story.append(Paragraph("Конфиденциальные данные не обнаружены.", normal))

    for item in findings:

        story.append(
            Paragraph(f"<b>{_escape(item.get('type', ''))} ({item.get('count', 0)})</b>", normal)
        )

        for raw_value in item.get("items", []):

            value, confidence = _value_and_confidence(raw_value)

            if confidence is not None:
                line = f"• {_escape(value)} <font color='#6b7280'>(уверенность: {round(float(confidence), 2)})</font>"
            else:
                line = f"• {_escape(value)}"

            story.append(Paragraph(line, normal))

        story.append(Spacer(1, 6))

    # =====================================================
    # Рекомендации
    # =====================================================

    story.append(Spacer(1, 10))
    story.append(Paragraph("Рекомендации", h))

    if risk in ("Высокий", "Критический"):
        recommendation = (
            "Обнаружены критичные конфиденциальные данные (реквизиты, секреты доступа "
            "или персональные данные). Отправка текста во внешние нейросетевые сервисы "
            "(ChatGPT, Claude, Gemini и др.) в текущем виде не рекомендуется. "
            "Выполните маскирование данных перед отправкой."
        )
    elif risk == "Средний":
        recommendation = (
            "Обнаружены потенциально конфиденциальные данные. Перед отправкой текста "
            "во внешние нейросетевые сервисы рекомендуется выполнить маскирование информации."
        )
    else:
        recommendation = (
            "Критичных данных практически не обнаружено. Перед отправкой текста "
            "рекомендуется выполнить повторную проверку."
        )

    story.append(Paragraph(recommendation, normal))

    story.append(Spacer(1, 25))
    story.append(Paragraph("Сформировано системой «Промпт-Щит»", small))

    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)

    return filepath


# =====================================================
# СВОДНЫЙ ОТЧЁТ (дневной / недельный / для руководителя ИБ)
#
# В отличие от generate_report() (результат ОДНОЙ проверки), здесь
# агрегируются данные за период — то, что в ТЗ названо "отчётами
# безопасности" и "отчётом для руководителя ИБ".
# =====================================================

def generate_summary_report(stats, activity, period_label, organization_name=None):

    _register_fonts()

    cfg = load_config()

    if not organization_name:
        organization_name = cfg.get("organization_name", "")

    filename = datetime.now().strftime(f"PromptShield_Summary_%Y%m%d_%H%M%S.pdf")
    filepath = data_path("reports", filename)

    doc = SimpleDocTemplate(
        filepath,
        rightMargin=18 * mm, leftMargin=18 * mm,
        topMargin=18 * mm, bottomMargin=18 * mm
    )

    styles = getSampleStyleSheet()

    title = styles["Title"]
    title.fontName = "DejaVu-Bold"
    title.alignment = TA_CENTER

    h = styles["Heading2"]
    h.fontName = "DejaVu-Bold"

    normal = styles["BodyText"]
    normal.fontName = "DejaVu"

    small = styles["BodyText"].clone("small2")
    small.fontName = "DejaVu"
    small.fontSize = 9
    small.textColor = HexColor("#6b7280")

    story = []

    story.append(Paragraph("ПРОМПТ-ЩИТ", title))
    story.append(Paragraph(f"Сводный отчёт по безопасности — {period_label}", normal))
    story.append(Spacer(1, 10))

    if organization_name:
        story.append(Paragraph(f"<b>Организация:</b> {_escape(organization_name)}", normal))

    story.append(Paragraph(f"<b>Сформирован:</b> {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}", normal))
    story.append(Spacer(1, 15))

    # ---------- Общая статистика ----------

    story.append(Paragraph("Общие показатели", h))

    overview = [
        ["Всего проверок за период", str(stats.get("checks_period", 0))],
        ["Проверок за всё время", str(stats.get("total_checks", 0))],
        ["Доля высокого/критического риска", f"{stats.get('high_risk_ratio', 0)}%"],
    ]

    t1 = Table(overview, colWidths=[110 * mm, 50 * mm])
    t1.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (-1, -1), "DejaVu"),
        ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#cccccc")),
        ("BACKGROUND", (0, 0), (0, -1), HexColor("#f3f4f6")),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))

    story.append(t1)
    story.append(Spacer(1, 15))

    # ---------- Распределение по риску ----------

    story.append(Paragraph("Распределение по уровню риска", h))

    risk_rows = [["Уровень риска", "Количество"]]
    for risk_name, count in stats.get("risk_counts", {}).items():
        risk_rows.append([risk_name, str(count)])

    t2 = Table(risk_rows, colWidths=[110 * mm, 50 * mm])
    t2.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), HexColor("#2563eb")),
        ("TEXTCOLOR", (0, 0), (-1, 0), HexColor("#ffffff")),
        ("FONTNAME", (0, 0), (-1, 0), "DejaVu-Bold"),
        ("FONTNAME", (0, 1), (-1, -1), "DejaVu"),
        ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#cccccc")),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))

    story.append(t2)
    story.append(Spacer(1, 15))

    # ---------- Наиболее частые типы данных ----------

    if stats.get("top_types"):

        story.append(Paragraph("Наиболее часто встречающиеся типы данных", h))

        type_rows = [["Тип", "Количество"]] + [[t, str(c)] for t, c in stats["top_types"]]

        t3 = Table(type_rows, colWidths=[110 * mm, 50 * mm])
        t3.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), HexColor("#2563eb")),
            ("TEXTCOLOR", (0, 0), (-1, 0), HexColor("#ffffff")),
            ("FONTNAME", (0, 0), (-1, 0), "DejaVu-Bold"),
            ("FONTNAME", (0, 1), (-1, -1), "DejaVu"),
            ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#cccccc")),
        ]))

        story.append(t3)
        story.append(Spacer(1, 15))

    # ---------- Активность пользователей ----------

    if activity:

        story.append(Paragraph("Активность пользователей (ориентировочная оценка риска)", h))

        act_rows = [["Пользователь", "Проверок", "Нарушений", "Оценка риска"]]

        for entry in activity:
            act_rows.append([
                entry["username"],
                str(entry["total_checks"]),
                str(entry["violations"]),
                f"{entry['risk_score']} / 100"
            ])

        t4 = Table(act_rows, colWidths=[60 * mm, 35 * mm, 35 * mm, 30 * mm])
        t4.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), HexColor("#2563eb")),
            ("TEXTCOLOR", (0, 0), (-1, 0), HexColor("#ffffff")),
            ("FONTNAME", (0, 0), (-1, 0), "DejaVu-Bold"),
            ("FONTNAME", (0, 1), (-1, -1), "DejaVu"),
            ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#cccccc")),
        ]))

        story.append(t4)
        story.append(Spacer(1, 10))

        story.append(Paragraph(
            "Оценка риска — ориентировочный показатель на основе истории проверок "
            "(средний уровень риска и доля проверок с высоким/критическим риском), "
            "не является точной метрикой поведения пользователя.",
            small
        ))

    story.append(Spacer(1, 20))
    story.append(Paragraph("Сформировано системой «Промпт-Щит»", small))

    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)

    return filepath
