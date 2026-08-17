"""Descubrimiento de equipos activos en el segmento.

Reúne las técnicas disponibles bajo una única fase con la firma que espera el
orquestador. Cada objetivo se sondea con todas las técnicas solicitadas y se
registra cuáles de ellas obtuvieron respuesta, en lugar de detenerse en la
primera que acierte. La ejecución completa cuesta más tiempo, pero produce el dato
que interesa al capítulo de casos de prueba: qué técnicas responden en qué
equipos, que es lo que permite sostener con medidas propias por qué el eco ICMP
por sí solo resulta insuficiente.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from ipaddress import IPv4Address

from ..core.modelo import Host, TecnicaDescubrimiento
from ..core.orquestador import Configuracion, en_paralelo
from . import icmp, tcp, udp
from ._scapy import ScapyNoDisponible, cargar
from .udp import ResultadoUDP

registro = logging.getLogger(__name__)

__all__ = ["ScapyNoDisponible", "cargar", "descubrir", "icmp", "tcp", "udp"]


def _sondear_host(direccion: IPv4Address, config: Configuracion) -> Host:
    host = Host(direccion=direccion)
    tecnicas = config.tecnicas_descubrimiento or [TecnicaDescubrimiento.ICMP]

    for tecnica in tecnicas:
        if tecnica is TecnicaDescubrimiento.ICMP:
            activo, ttl = icmp.sondear(direccion, config.espera_s, config.limitador)
        elif tecnica is TecnicaDescubrimiento.TCP:
            activo, ttl = tcp.sondear(
                direccion, config.puerto_ping_tcp, config.espera_s, config.limitador
            )
        elif tecnica is TecnicaDescubrimiento.UDP:
            resultado, ttl = udp.sondear(
                direccion, config.puerto_ping_udp, config.espera_s, config.limitador
            )
            activo = resultado is ResultadoUDP.ACTIVO
        else:
            # ARP se incorpora en su propia jornada; omitirla en silencio sería
            # peor que registrar que no se ejecutó.
            registro.debug("técnica de descubrimiento no implementada: %s", tecnica.value)
            continue

        if activo:
            host.activo = True
            host.tecnicas_respondidas.append(tecnica)
            # El tiempo de vida solo se conserva la primera vez que se observa:
            # todas las técnicas miden el mismo valor del mismo objetivo.
            if host.ttl_observado is None and ttl is not None:
                host.ttl_observado = ttl

    return host


def descubrir(objetivos: Sequence[IPv4Address], config: Configuracion) -> list[Host]:
    """Fase de descubrimiento. Devuelve un ``Host`` por objetivo, activo o no."""
    hosts = en_paralelo(
        lambda d: _sondear_host(d, config), objetivos, config.trabajadores
    )
    hosts.sort(key=lambda h: int(h.direccion))

    activos = [h for h in hosts if h.activo]
    registro.info(
        "descubrimiento: %d activos de %d objetivos con %s",
        len(activos),
        len(hosts),
        ", ".join(t.value for t in config.tecnicas_descubrimiento) or "icmp",
    )
    return hosts
