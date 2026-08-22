"""Extracción heurística de nombre y versión a partir de un banner.

El apartado 3.4.2 de la memoria expone la técnica: un banner es una declaración
del propio servicio acerca de sí mismo y no una prueba de la versión que ejecuta,
de modo que la extracción constituye una hipótesis informativa y de coste
reducido, no una certeza. La opción alternativa —inferir la versión a partir del
comportamiento del servicio ante sondas discriminantes— exige una base de firmas
del volumen que mantiene la herramienta de referencia y queda fuera del alcance
del trabajo.

Este módulo aplica un conjunto reducido de patrones heurísticos que cubren la
mayor parte de los mensajes de bienvenida habituales, sin recurrir a una regla
por servicio. El diseño responde a la decisión formal que acompaña al módulo: se
demuestra la técnica con un mecanismo mínimo, y la comparativa del capítulo
sexto medirá la precisión que se alcanza con esta aproximación frente a la
herramienta de referencia.
"""

from __future__ import annotations

import re

# Los patrones se prueban en orden y se detienen en el primero que coincida. El
# orden importa: los más específicos van antes que los que abarcan más casos, y
# los que discriminan claramente el nombre del servicio van antes que los que
# solo extraen la versión.
#
# Los grupos con nombre son deliberados: aportan claridad y permiten que un
# patrón devuelva solo versión sin nombre, o solo nombre sin versión, sin tener
# que interpretar posiciones ordinales.
_PATRONES: tuple[tuple[str, re.Pattern[str]], ...] = (
    # SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.15
    ("ssh", re.compile(r"^SSH-\d\.\d-(?P<nombre>[^\s_]+)[_\s](?P<version>[^\s]+)")),
    # HTTP: cabecera Server. La cabecera se separa antes; aquí llega ya el valor.
    #   Apache/2.4.58 (Ubuntu) / nginx/1.24.0 / Microsoft-IIS/10.0
    ("servidor_http", re.compile(r"^(?P<nombre>[A-Za-z][\w\-.]+)/(?P<version>[\w.\-]+)")),
    # SMTP: 220 host.dom ESMTP Postfix (Ubuntu)  |  220 host ESMTP Exim 4.94
    ("smtp_esmtp", re.compile(r"\bESMTP\s+(?P<nombre>[A-Za-z][\w\-.]*)(?:\s+(?P<version>[\d.][\w.\-]*))?")),
    # FTP:  220 (vsFTPd 3.0.3)  |  220 ProFTPD 1.3.7 Server
    ("ftp_paren", re.compile(r"^220[\s-].*?\(?\b(?P<nombre>[A-Za-z][\w\-]+)\s+(?P<version>[\d.][\w.\-]*)\)?")),
    # MySQL/MariaDB en el saludo binario: la versión aparece en ASCII separada por 0x00.
    #   5.5.61-0ubuntu0.14.04.1  |  8.0.32  |  10.6.12-MariaDB-1
    ("mysql", re.compile(r"(?P<version>\d+\.\d+(?:\.\d+)?[\w.\-]+)")),
    # Genérico «nombre/versión» en cualquier posición: cubre productos que se
    # anuncian como «Producto/1.2.3» dentro de un texto más amplio.
    ("generico_barra", re.compile(r"\b(?P<nombre>[A-Za-z][\w\-.]{1,30})/(?P<version>\d[\w.\-]*)")),
    # Genérico «nombre versión» con versión numérica, más laxo. Se usa como
    # último recurso porque produce falsos positivos con facilidad; queda al
    # final para que los patrones específicos tengan oportunidad primero.
    ("generico_espacio", re.compile(
        r"\b(?P<nombre>[A-Za-z][\w\-]{2,30})\s+v?(?P<version>\d+\.\d+(?:\.\d+)?[\w.\-]*)"
    )),
)

_PATRON_MYSQL = next(p for n, p in _PATRONES if n == "mysql")


def _es_patron_mysql(patron: re.Pattern[str]) -> bool:
    """Indica si el patrón dado es el que reconoce el formato de versión MySQL.

    Se prefiere esta comparación por identidad a exponer el nombre del patrón
    fuera del módulo: los nombres son detalle interno, mientras que la relación
    entre un patrón y su singularidad de post-proceso es lo que aquí importa.
    """
    return patron is _PATRON_MYSQL


def extraer(banner: str) -> tuple[str | None, str | None]:
    """Extrae nombre y versión de un banner.

    Devuelve ``(nombre, versión)`` con cualquiera de los dos como ``None`` si el
    patrón que coincide no aporta ese componente. Ambos ``None`` significa que
    ninguno de los patrones fue aplicable: la política del proyecto es preferir
    la ausencia de dato a una interpretación forzada.
    """
    if not banner:
        return None, None

    # Se examinan solo los primeros bytes: los banners útiles son cortos y los
    # patrones diseñados para operar sobre saludos, no sobre respuestas largas.
    fragmento = banner[:512]

    for _nombre_patron, patron in _PATRONES:
        coincidencia = patron.search(fragmento)
        if coincidencia is None:
            continue
        grupos = coincidencia.groupdict()
        nombre = grupos.get("nombre")
        version = grupos.get("version")
        # El patrón mysql solo captura la versión numérica: la marca del
        # producto se infiere aquí a partir del banner completo. MariaDB tiene
        # prioridad sobre MySQL porque el saludo binario de MariaDB también
        # anuncia una versión con el formato de MySQL; MySQL puro, en cambio, no
        # menciona nunca MariaDB.
        if nombre is None and version:
            if "MariaDB" in fragmento:
                nombre = "MariaDB"
            elif _es_patron_mysql(patron):
                nombre = "MySQL"
        if nombre or version:
            return nombre, version

    return None, None
