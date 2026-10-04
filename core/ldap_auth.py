"""
Интеграция с корпоративным LDAP / Active Directory.

Требует пакет `ldap3` (pip install ldap3) и реальный LDAP/AD-сервер
компании. Без библиотеки или при отключённой настройке модуль просто
сообщает об этом и не мешает работе локальной аутентификации.
"""

import logging

logger = logging.getLogger("promptshield.ldap_auth")

try:
    import ldap3
except ImportError:
    ldap3 = None


def is_available():
    return ldap3 is not None


def ldap_authenticate(username, password, ldap_config):
    """
    Пытается выполнить bind к LDAP/AD-серверу с указанными учётными
    данными пользователя.

    ldap_config — словарь из config.json:
    {
        "enabled": bool,
        "server": "ldap://dc.company.local",
        "user_dn_template": "{username}@company.local",  # или полный DN
        "base_dn": "DC=company,DC=local",
        "use_ssl": bool
    }

    Возвращает True/False. None — если LDAP недоступен/не настроен
    (в этом случае вызывающий код должен использовать локальную
    аутентификацию как запасной вариант).
    """

    if not ldap_config or not ldap_config.get("enabled"):
        return None

    if ldap3 is None:
        logger.warning("LDAP включён в настройках, но пакет ldap3 не установлен")
        return None

    server_url = ldap_config.get("server")
    template = ldap_config.get("user_dn_template", "{username}")

    if not server_url:
        logger.warning("LDAP включён, но не указан адрес сервера")
        return None

    bind_dn = template.format(username=username)

    try:
        server = ldap3.Server(server_url, use_ssl=ldap_config.get("use_ssl", False))

        conn = ldap3.Connection(
            server,
            user=bind_dn,
            password=password,
            auto_bind=True,
            raise_exceptions=True
        )

        conn.unbind()
        return True

    except Exception as e:
        logger.info("LDAP bind не удался для %s: %s", username, e)
        return False


def ldap_user_role(username, password, ldap_config, admin_group_dn=None):
    """
    Опционально: определяет роль пользователя по членству в группе AD.
    Если группа администраторов не задана — все успешно
    аутентифицированные LDAP-пользователи получают роль 'analyst'
    (безопасное значение по умолчанию — права на изменение настроек
    нужно выдавать явно).
    """

    if not admin_group_dn or ldap3 is None:
        return "analyst"

    try:
        server = ldap3.Server(ldap_config.get("server"), use_ssl=ldap_config.get("use_ssl", False))
        template = ldap_config.get("user_dn_template", "{username}")
        bind_dn = template.format(username=username)

        conn = ldap3.Connection(server, user=bind_dn, password=password, auto_bind=True)

        conn.search(
            search_base=ldap_config.get("base_dn", ""),
            search_filter=f"(sAMAccountName={username})",
            attributes=["memberOf"]
        )

        if conn.entries:
            groups = [str(g) for g in conn.entries[0].memberOf]
            if admin_group_dn in groups:
                return "admin"

        conn.unbind()

    except Exception as e:
        logger.info("Не удалось определить роль LDAP-пользователя %s: %s", username, e)

    return "analyst"
