"""Descubrimiento de equipos mediante ICMP Echo Request.

Es la técnica clásica: se envía una solicitud de eco y se interpreta la respuesta
como prueba de que el equipo está activo. Su fiabilidad ha disminuido con el
tiempo porque numerosos sistemas y cortafuegos descartan este tráfico por
defecto; el cortafuegos de Windows lo hace en sus perfiles públicos, por ejemplo.
Esa limitación es precisamente la razón de que existan las técnicas basadas en
TCP y UDP, y conviene contrastarla en el banco de pruebas.

Aporta además un dato que ninguna otra técnica de descubrimiento proporciona con
tan poco coste: el tiempo de vida de la respuesta, que constituye una de las
señales de peso alto del modelo de detección de sistema operativo (decisión 013).
"""

from __future__ import annotations

import logging
import time
from ipaddress import IPv4Address

from ._scapy import cargar

registro = logging.getLogger(__name__)

# Tipos de mensaje ICMP relevantes.
ECHO_REPLY = 0
DESTINO_INALCANZABLE = 3

# Códigos del mensaje de destino inalcanzable que denotan filtrado deliberado y
# no ausencia del equipo. Su recepción prueba que existe un dispositivo en el
# camino que descarta el tráfico, lo que a efectos de descubrimiento significa
# que la red del objetivo es alcanzable aunque él no responda.
CODIGOS_PROHIBIDO_ADMINISTRATIVAMENTE = {1, 2, 3, 9, 10, 13}


def sondear(
    direccion: IPv4Address,
    espera_s: float,
    limitador=None,
) -> tuple[bool, int | None]:
    """Envía una solicitud de eco y devuelve si el equipo responde y su tiempo de vida.

    El segundo elemento de la tupla es el tiempo de vida observado en la
    respuesta, o ``None`` si no la hubo.
    """
    scapy = cargar()

    if limitador is not None:
        limitador.acquire()
    try:
        paquete = scapy.IP(dst=str(direccion)) / scapy.ICMP()
        respuesta = scapy.sr1(paquete, timeout=espera_s, verbose=0)
    except OSError as exc:  # pragma: no cover - depende de la red
        registro.debug("ICMP hacia %s: %s", direccion, exc)
        return False, None
    finally:
        if limitador is not None:
            limitador.release()

    if respuesta is None:
        return False, None

    if not respuesta.haslayer(scapy.ICMP):
        return False, None

    tipo = int(respuesta[scapy.ICMP].type)
    ttl = int(respuesta[scapy.IP].ttl)

    if tipo == ECHO_REPLY:
        return True, ttl

    # Un mensaje de inalcanzable procede de un dispositivo intermedio, de modo
    # que su tiempo de vida no caracteriza al objetivo y no debe emplearse como
    # señal de sistema operativo.
    if tipo == DESTINO_INALCANZABLE:
        codigo = int(respuesta[scapy.ICMP].code)
        registro.debug("ICMP inalcanzable desde %s, código %d", direccion, codigo)
        return False, None

    return False, None


def medir(direccion: IPv4Address, espera_s: float, limitador=None) -> tuple[bool, int | None, float]:
    """Variante de :func:`sondear` que devuelve además el tiempo de ida y vuelta."""
    inicio = time.perf_counter()
    activo, ttl = sondear(direccion, espera_s, limitador)
    return activo, ttl, round((time.perf_counter() - inicio) * 1000, 2)
