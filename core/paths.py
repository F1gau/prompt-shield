"""
Разрешение путей к ресурсам и данным приложения.

Зачем этот модуль вообще нужен: при обычном запуске (`python app.py`)
всё лежит в одной папке проекта — и код, и config.json, и логи, и
шрифты. Но при сборке в один .exe через PyInstaller это перестаёт быть
так:

- Код и статические ресурсы (templates/, static/, fonts/) PyInstaller
  распаковывает во ВРЕМЕННУЮ папку (sys._MEIPASS), которая создаётся
  заново при каждом запуске и удаляется при выходе из программы.
- Если писать config.json, базу данных или PDF-отчёты в эту же
  временную папку — они будут бесследно исчезать после каждого
  перезапуска, что для DLP-системы, которая обязана хранить журнал
  инцидентов, неприемлемо.

Поэтому: ресурсы только для чтения читаем из `get_resource_dir()`,
а всё, что должно сохраняться между запусками (конфигурация, база
инцидентов, сгенерированные отчёты) — из `get_data_dir()`, которая
при сборке в exe указывает на папку РЯДОМ с самим exe-файлом, а не
внутрь временной распаковки.
"""

import os
import sys


def is_frozen() -> bool:
    """True, если приложение запущено как собранный PyInstaller-exe."""
    return getattr(sys, "frozen", False)


def get_resource_dir() -> str:
    """
    Папка с ресурсами только для чтения: templates/, static/, fonts/,
    сам код приложения. Внутри exe — это временная папка распаковки
    PyInstaller (sys._MEIPASS); при обычном запуске — корень проекта.
    """

    if is_frozen():
        return getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(sys.executable)))

    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def get_data_dir() -> str:
    """
    Папка для данных, которые должны переживать перезапуск программы:
    config.json, logs/ (в т.ч. SQLite-база), reports/. Внутри exe —
    папка РЯДОМ с exe-файлом (не временная распаковка); при обычном
    запуске — корень проекта, как и раньше.
    """

    override = os.environ.get("PROMPTSHIELD_DATA_DIR")

    if override:
        # явно заданная папка данных (удобно для тестов и развёртывания:
        # config.json, база и отчёты лежат отдельно от исходников)
        base = os.path.abspath(override)
    elif is_frozen():
        base = os.path.dirname(os.path.abspath(sys.executable))
    else:
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    os.makedirs(base, exist_ok=True)

    return base


def data_path(*parts) -> str:
    """Путь внутри писчей папки данных, с автоматическим созданием
    промежуточных каталогов (logs/, reports/ и т.п.)."""

    path = os.path.join(get_data_dir(), *parts)
    os.makedirs(os.path.dirname(path), exist_ok=True)

    return path


def resource_path(*parts) -> str:
    """Путь внутри папки ресурсов только для чтения (templates, static, fonts)."""

    return os.path.join(get_resource_dir(), *parts)
