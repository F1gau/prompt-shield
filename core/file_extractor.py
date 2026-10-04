import os
import io
import csv
import zipfile
import logging


logger = logging.getLogger("promptshield.file_extractor")


# ==================================================
# OPTIONAL DEPENDENCIES (graceful degradation)
# ==================================================

try:
    import pdfplumber
except ImportError:
    pdfplumber = None

try:
    import docx
except ImportError:
    docx = None

try:
    import openpyxl
except ImportError:
    openpyxl = None

try:
    from pptx import Presentation
except ImportError:
    Presentation = None

try:
    import pytesseract
    from PIL import Image
except ImportError:
    pytesseract = None
    Image = None


SUPPORTED_EXTENSIONS = {
    ".txt", ".pdf", ".docx", ".csv", ".xlsx", ".pptx", ".log", ".json",
    ".jpg", ".jpeg", ".png", ".webp"
}

# максимальная сторона изображения перед OCR (в пикселях) — очень
# крупные фото (12+ мегапикселей с телефона) не улучшают точность
# распознавания, но заметно замедляют обработку; уменьшаем перед OCR
MAX_OCR_IMAGE_DIMENSION = 3000

# минимальное число символов текста на страницу PDF, ниже которого
# документ считается "скорее всего сканом" и запускается OCR
OCR_TRIGGER_THRESHOLD = 20

# максимум страниц, которые прогоняем через OCR за один документ
# (OCR — дорогая операция, защита от чрезмерной нагрузки)
MAX_OCR_PAGES = 30


# ==================================================
# СИГНАТУРЫ ФАЙЛОВ (защита от подмены расширения)
# ==================================================

def detect_real_kind(file_path):
    """
    Определяет реальный тип файла по сигнатуре (magic bytes),
    независимо от расширения в имени файла. Возвращает один из:
    'pdf', 'zip' (docx/xlsx/pptx — все являются zip-контейнерами),
    'text', 'unknown'.
    """

    try:
        with open(file_path, "rb") as f:
            head = f.read(16)
    except OSError:
        return "unknown"

    if head.startswith(b"%PDF"):
        return "pdf"

    if head.startswith(b"PK\x03\x04") or head.startswith(b"PK\x05\x06") or head.startswith(b"PK\x07\x08"):
        return "zip"

    if head.startswith(b"\xff\xd8\xff"):
        return "jpeg"

    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"

    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "webp"

    # Текстовые файлы не имеют фиксированной сигнатуры. Раньше здесь
    # проверялась строгая декодируемость как UTF-8 — но это ложно
    # отклоняло совершенно легитимные файлы в кодировке Windows-1251
    # (обычная кодировка выгрузок из 1С и старого ПО), поскольку
    # кириллица в cp1251 не является валидной UTF-8-последовательностью.
    # Вместо этого используем более надёжный признак бинарности —
    # наличие NUL-байтов, которых в текстовых файлах не бывает.
    if b"\x00" in head:
        return "unknown"

    return "text"


def _zip_office_kind(file_path):
    """Уточняет тип office-контейнера (docx/xlsx/pptx) по внутренней структуре."""

    try:
        with zipfile.ZipFile(file_path) as z:
            names = z.namelist()
    except Exception:
        return None

    if any(n.startswith("word/") for n in names):
        return ".docx"

    if any(n.startswith("xl/") for n in names):
        return ".xlsx"

    if any(n.startswith("ppt/") for n in names):
        return ".pptx"

    return None


def validate_file_signature(file_path, claimed_ext):
    """
    Проверяет, что реальное содержимое файла соответствует заявленному
    расширению. Возвращает (True, None) если всё в порядке, иначе
    (False, "причина").
    """

    claimed_ext = claimed_ext.lower()
    kind = detect_real_kind(file_path)

    if claimed_ext == ".pdf":
        if kind != "pdf":
            return False, "Содержимое файла не соответствует формату PDF"
        return True, None

    if claimed_ext in (".docx", ".xlsx", ".pptx"):
        if kind != "zip":
            return False, f"Содержимое файла не соответствует формату {claimed_ext}"

        real = _zip_office_kind(file_path)

        if real and real != claimed_ext:
            return False, f"Файл с расширением {claimed_ext} на самом деле является {real}"

        return True, None

    if claimed_ext in (".txt", ".csv", ".log", ".json"):
        if kind == "unknown":
            return False, "Файл не является текстовым (бинарное содержимое)"
        return True, None

    if claimed_ext in (".jpg", ".jpeg"):
        if kind != "jpeg":
            return False, "Содержимое файла не соответствует формату JPEG"
        return True, None

    if claimed_ext == ".png":
        if kind != "png":
            return False, "Содержимое файла не соответствует формату PNG"
        return True, None

    if claimed_ext == ".webp":
        if kind != "webp":
            return False, "Содержимое файла не соответствует формату WEBP"
        return True, None

    return False, f"Формат {claimed_ext} не поддерживается"


# ==================================================
# MAIN ENTRY (простая обёртка для обратной совместимости)
# ==================================================

def extract_text_from_file(file_path, ext=None):
    return extract_text_with_meta(file_path, ext=ext)["text"]


def extract_text_with_meta(file_path, ext=None):
    """
    Извлекает текст из файла и возвращает метаданные извлечения:
    {
        "text": "...",
        "method": "native" | "ocr" | "empty",
        "pages_ocr": int,
        "warning": str | None
    }
    """

    if ext is None:
        ext = os.path.splitext(file_path)[1].lower()
    else:
        ext = ext.lower()

    meta = {"text": "", "method": "empty", "pages_ocr": 0, "warning": None}

    try:

        if ext == ".txt":
            meta["text"] = extract_txt(file_path)
            meta["method"] = "native" if meta["text"].strip() else "empty"

        elif ext == ".log":
            meta["text"] = extract_log(file_path)
            meta["method"] = "native" if meta["text"].strip() else "empty"

        elif ext == ".json":
            meta["text"] = extract_json_file(file_path)
            meta["method"] = "native" if meta["text"].strip() else "empty"

        elif ext == ".csv":
            meta["text"] = extract_csv(file_path)
            meta["method"] = "native" if meta["text"].strip() else "empty"

        elif ext == ".pdf":
            meta = extract_pdf_with_meta(file_path)

        elif ext == ".docx":
            meta["text"] = extract_docx(file_path)
            meta["method"] = "native" if meta["text"].strip() else "empty"

        elif ext == ".xlsx":
            meta["text"] = extract_xlsx(file_path)
            meta["method"] = "native" if meta["text"].strip() else "empty"

        elif ext == ".pptx":
            meta["text"] = extract_pptx(file_path)
            meta["method"] = "native" if meta["text"].strip() else "empty"

        elif ext in (".jpg", ".jpeg", ".png", ".webp"):
            meta = extract_image_with_meta(file_path)

        else:
            meta["warning"] = f"Формат {ext} не поддерживается"

    except Exception as e:
        logger.exception("Ошибка извлечения текста из файла %s", file_path)
        meta["warning"] = f"Ошибка при обработке файла: {e}"

    return meta


# ==================================================
# TXT
#
# Файлы из российских корпоративных систем (1С, старый софт,
# экспорт из Excel) часто сохраняются в Windows-1251, а не в UTF-8.
# Простое "utf-8 + errors=ignore" в таком случае молча превращает
# всю кириллицу в мусор — детекторы просто не находят ПДн в таких
# файлах, создавая ложное чувство безопасности. Поэтому пробуем
# несколько кодировок по очереди и берём первую, которая
# декодируется без ошибок.
# ==================================================

TEXT_ENCODINGS = ("utf-8-sig", "utf-8", "cp1251", "cp866", "latin-1")


def read_text_robust(file_path):

    with open(file_path, "rb") as f:
        raw = f.read()

    for encoding in TEXT_ENCODINGS:
        try:
            return raw.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            continue

    # latin-1 технически не выбрасывает UnicodeDecodeError почти
    # никогда (принимает любые байты), поэтому этот код —
    # подстраховка на случай экзотических повреждений файла
    return raw.decode("utf-8", errors="ignore")


def extract_txt(file_path):
    return read_text_robust(file_path)


# ==================================================
# LOG / JSON (текстовые форматы, читаются так же, как TXT)
# ==================================================

def extract_log(file_path):
    return read_text_robust(file_path)


def extract_json_file(file_path):
    return read_text_robust(file_path)


# ==================================================
# CSV
# ==================================================

def extract_csv(file_path):

    text_rows = []

    content = read_text_robust(file_path)
    reader = csv.reader(io.StringIO(content))

    for row in reader:
        text_rows.append(" ".join(row))

    return "\n".join(text_rows).strip()


# ==================================================
# PDF (с OCR-фолбэком для сканов)
# ==================================================

def extract_pdf_with_meta(file_path):

    meta = {"text": "", "method": "empty", "pages_ocr": 0, "warning": None}

    if pdfplumber is None:
        meta["warning"] = "Модуль pdfplumber не установлен — PDF не может быть обработан"
        return meta

    native_pages = []
    weak_pages = []  # индексы страниц, где текста мало или нет вовсе

    with pdfplumber.open(file_path) as pdf:

        for i, page in enumerate(pdf.pages):

            page_text = page.extract_text() or ""
            native_pages.append(page_text)

            if len(page_text.strip()) < OCR_TRIGGER_THRESHOLD:
                weak_pages.append(i)

    full_text = "\n".join(p for p in native_pages if p).strip()

    # если весь текст извлёкся нормально — OCR не нужен
    if not weak_pages:
        meta["text"] = full_text
        meta["method"] = "native" if full_text else "empty"
        return meta

    # похоже на сканированный документ — пробуем OCR только по "слабым" страницам
    if pytesseract is None or Image is None:
        meta["text"] = full_text
        meta["method"] = "native" if full_text else "empty"
        meta["warning"] = (
            "Часть страниц похожа на сканы без текстового слоя. "
            "OCR недоступен (не установлен pytesseract/Pillow или Tesseract-OCR "
            "в системе) — текст с этих страниц не извлечён."
        )
        return meta

    ocr_pages_done = 0
    ocr_texts = list(native_pages)

    with pdfplumber.open(file_path) as pdf:

        for i in weak_pages:

            if ocr_pages_done >= MAX_OCR_PAGES:
                meta["warning"] = (
                    f"Достигнут лимит OCR-страниц ({MAX_OCR_PAGES}); "
                    "оставшиеся сканы не обработаны."
                )
                break

            try:
                page_image = pdf.pages[i].to_image(resolution=200).original

                try:
                    text = pytesseract.image_to_string(page_image, lang="rus+eng")
                except Exception:
                    # языковые данные rus могут быть не установлены на сервере —
                    # пробуем только английский, чтобы не потерять всё
                    text = pytesseract.image_to_string(page_image, lang="eng")

                ocr_texts[i] = text
                ocr_pages_done += 1

            except Exception as e:
                logger.warning("OCR не удался для страницы %s: %s", i, e)

    meta["text"] = "\n".join(t for t in ocr_texts if t).strip()
    meta["method"] = "ocr" if ocr_pages_done else ("native" if full_text else "empty")
    meta["pages_ocr"] = ocr_pages_done

    return meta


def extract_pdf(file_path):
    return extract_pdf_with_meta(file_path)["text"]


# ==================================================
# ИЗОБРАЖЕНИЯ (JPG/PNG/WEBP) — прямой OCR
#
# Используется тот же движок Tesseract, что и для сканированных
# страниц PDF, просто без промежуточного рендеринга страницы в
# картинку — здесь файл уже картинка. Типичный сценарий: сотрудник
# фотографирует документ на телефон или делает скриншот переписки
# и загружает файл напрямую, а не как часть PDF.
# ==================================================

def extract_image_with_meta(file_path):

    meta = {"text": "", "method": "empty", "pages_ocr": 0, "warning": None}

    if pytesseract is None or Image is None:
        meta["warning"] = (
            "OCR недоступен (не установлен pytesseract/Pillow или "
            "Tesseract-OCR в системе) — текст с изображения не извлечён."
        )
        return meta

    try:
        img = Image.open(file_path)

        # приводим к RGB — некоторые PNG с прозрачностью (RGBA) или
        # палитровые изображения Tesseract обрабатывает менее надёжно
        if img.mode not in ("RGB", "L"):
            img = img.convert("RGB")

        # очень крупные фото с телефона (10+ мегапикселей) не дают
        # прироста точности распознавания, но заметно замедляют OCR —
        # уменьшаем до разумного максимума по большей стороне
        if max(img.size) > MAX_OCR_IMAGE_DIMENSION:
            scale = MAX_OCR_IMAGE_DIMENSION / max(img.size)
            new_size = (round(img.size[0] * scale), round(img.size[1] * scale))
            img = img.resize(new_size, Image.LANCZOS)

        try:
            text = pytesseract.image_to_string(img, lang="rus+eng")
        except Exception:
            # языковые данные rus могут быть не установлены на сервере —
            # пробуем только английский, чтобы не потерять всё распознавание
            text = pytesseract.image_to_string(img, lang="eng")

        meta["text"] = text.strip()
        meta["method"] = "ocr" if meta["text"] else "empty"
        meta["pages_ocr"] = 1 if meta["text"] else 0

        if not meta["text"]:
            meta["warning"] = (
                "На изображении не распознан текст. Возможные причины: "
                "низкое качество/разрешение фото, текст на изображении "
                "отсутствует, либо изображение сильно повёрнуто/размыто."
            )

    except Exception as e:
        logger.warning("OCR не удался для изображения %s: %s", file_path, e)
        meta["warning"] = f"Не удалось обработать изображение: {e}"

    return meta


# ==================================================
# DOCX (параграфы + таблицы)
# ==================================================

def extract_docx(file_path):

    if docx is None:
        return ""

    document = docx.Document(file_path)
    parts = []

    for para in document.paragraphs:
        if para.text:
            parts.append(para.text)

    for table in document.tables:
        for row in table.rows:
            cells = [c.text for c in row.cells if c.text]
            if cells:
                parts.append(" | ".join(cells))

    return "\n".join(parts).strip()


# ==================================================
# XLSX
# ==================================================

def extract_xlsx(file_path):

    if openpyxl is None:
        return ""

    wb = openpyxl.load_workbook(file_path, data_only=True, read_only=True)
    parts = []

    for sheet in wb.worksheets:
        for row in sheet.iter_rows(values_only=True):
            cells = [str(v) for v in row if v is not None]
            if cells:
                parts.append(" ".join(cells))

    return "\n".join(parts).strip()


# ==================================================
# PPTX
# ==================================================

def extract_pptx(file_path):

    if Presentation is None:
        return ""

    prs = Presentation(file_path)
    parts = []

    for slide in prs.slides:
        for shape in slide.shapes:

            if shape.has_text_frame:
                for para in shape.text_frame.paragraphs:
                    text = "".join(run.text for run in para.runs)
                    if text:
                        parts.append(text)

            if shape.has_table:
                for row in shape.table.rows:
                    cells = [cell.text for cell in row.cells if cell.text]
                    if cells:
                        parts.append(" | ".join(cells))

    return "\n".join(parts).strip()


# ==================================================
# MEMORY INPUT SUPPORT (bytes -> текст, без записи на диск)
# ==================================================

def extract_text_from_bytes(file_bytes, filename):

    ext = os.path.splitext(filename)[1].lower()

    try:

        if ext == ".txt":
            return file_bytes.decode("utf-8", errors="ignore")

        if ext == ".csv":
            text_rows = []
            reader = csv.reader(io.StringIO(file_bytes.decode("utf-8", errors="ignore")))
            for row in reader:
                text_rows.append(" ".join(row))
            return "\n".join(text_rows).strip()

        if ext == ".pdf" and pdfplumber:
            text = ""
            with pdfplumber.open(io.BytesIO(file_bytes)) as pdf:
                for page in pdf.pages:
                    page_text = page.extract_text()
                    if page_text:
                        text += page_text + "\n"
            return text.strip()

        if ext == ".docx" and docx:
            document = docx.Document(io.BytesIO(file_bytes))
            return "\n".join(p.text for p in document.paragraphs)

        if ext == ".xlsx" and openpyxl:
            wb = openpyxl.load_workbook(io.BytesIO(file_bytes), data_only=True, read_only=True)
            parts = []
            for sheet in wb.worksheets:
                for row in sheet.iter_rows(values_only=True):
                    cells = [str(v) for v in row if v is not None]
                    if cells:
                        parts.append(" ".join(cells))
            return "\n".join(parts).strip()

        return ""

    except Exception as e:
        logger.exception("Ошибка извлечения текста из bytes (%s)", filename)
        return ""
