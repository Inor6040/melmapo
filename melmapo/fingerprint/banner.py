"""Identificación de servicios mediante lectura del banner de bienvenida.

El apartado 3.4.2 de la memoria describe la técnica. Numerosos servicios
—transferencia de ficheros, acceso remoto seguro, correo electrónico, bases de
datos— contemplan en su especificación un mensaje inicial que las
implementaciones habituales aprovechan para declarar el nombre del programa y su
versión. El módulo se limita a conectar y leer: no envía estímulo alguno, de modo
que los servicios que no hablan por iniciativa propia —el caso más frecuente es
HTTP, cubierto por su módulo específico— quedan aquí sin identificar y son
recogidos por la fase siguiente.

El diseño invierte deliberadamente la solución más obvia, consistente en enviar
un estímulo genérico a todo puerto abierto. Se descartó por dos motivos: el
estímulo produce ruido innecesario en las trazas de servicios que ya iban a
declararse por sí solos —un ``GET`` recibido por SSH o SMTP se registra como un
intento de acceso malformado—, y en protocolos binarios como MySQL provoca el
cierre de la conexión antes de haber leído el saludo. Leer primero y estimular
solo lo que resulte necesario es la lectura correcta del apartado 3.4.2.
"""

from __future__ import annotations

import logging
from typing import Callable

from ..core.modelo import EstadoPuerto, Host, Puerto, Servicio
from ..core.orquestador import Configuracion, en_paralelo
from . import extraccion
from .red import dialogar as _dialogar

registro = logging.getLogger(__name__)


def identificar_puerto(
    direccion: str,
    puerto: Puerto,
    espera_s: float,
    dialogar: Callable[[str, int, float], str | None] = _dialogar,
) -> None:
    """Rellena ``puerto.servicio`` a partir del banner que emita al conectar.

    Modifica el argumento en lugar de devolver un valor: la función forma parte
    de una fase que recorre una lista mutable de puertos, y este contrato encaja
    con el modelo de orquestación del proyecto.
    """
    banner = dialogar(direccion, puerto.numero, espera_s)
    if banner is None:
        return

    nombre, version = extraccion.extraer(banner)
    puerto.servicio = Servicio(
        nombre=nombre,
        version=version,
        banner_bruto=banner,
    )
    registro.debug(
        "banner de %s:%d: nombre=%r versión=%r", direccion, puerto.numero, nombre, version,
    )


def identificar_host(host: Host, config: Configuracion) -> Host:
    """Identifica el servicio de todos los puertos abiertos de un host.

    Los puertos no abiertos no se examinan: la técnica requiere establecer una
    conexión, que precisamente lo abierto es aquello a lo que se puede conectar.
    Los que ya tuvieran servicio identificado por otra técnica se dejan
    intactos, en previsión del orden de fases que se acuerde en el capítulo
    quinto.

    Los puertos pendientes se sondean en paralelo con la cota específica del
    fingerprint. Sin paralelización, un rango amplio en el que abundara HTTP en
    silencio agotaría un temporizador completo por cada puerto sondeado, lo que
    haría inviable el análisis en escenarios con decenas de puertos abiertos por
    host.
    """
    direccion = str(host.direccion)
    pendientes = [
        p for p in host.puertos
        if p.estado is EstadoPuerto.ABIERTO
        and (p.servicio is None or not p.servicio.esta_identificado())
    ]
    if not pendientes:
        return host

    en_paralelo(
        lambda p: identificar_puerto(direccion, p, config.espera_s, _dialogar),
        pendientes,
        config.trabajadores_fingerprint,
    )
    return host
