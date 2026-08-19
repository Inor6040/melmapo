"""Descubrimiento de equipos activos en el segmento.

Reúne las técnicas disponibles bajo una única fase con la firma que espera el
orquestador. Cada objetivo se sondea con todas las técnicas solicitadas y se
registra cuáles obtuvieron respuesta, en lugar de detenerse en la primera que
acierte (decisión 017). La ejecución completa cuesta más tiempo, pero produce el
dato que interesa al capítulo de casos de prueba: qué técnicas responden en qué
equipos, que es lo que permite sostener con medidas propias por qué el eco ICMP
por sí solo resulta insuficiente.

El ARP Ping recibe un tratamiento distinto del resto por una razón de fondo. Las
demás técnicas sondean un objetivo cada vez y bloquean el hilo hasta recibir
respuesta o agotar el plazo, de modo que su coste crece con el número de
objetivos. ARP, en cambio, admite despachar la barrida completa en una sola
operación y recoger después las respuestas. Se ejecuta por ello antes que las
demás, sobre el conjunto entero, y su resultado se consulta luego para cada
equipo.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from ipaddress import IPv4Address

from ..core.modelo import Host, TecnicaDescubrimiento
from ..core.orquestador import Configuracion, en_paralelo
from . import arp, icmp, tcp, udp
from ._scapy import ScapyNoDisponible, cargar
from .udp import ResultadoUDP

registro = logging.getLogger(__name__)

__all__ = ["ScapyNoDisponible", "arp", "cargar", "descubrir", "icmp", "tcp", "udp"]


def _sondear_host(
    direccion: IPv4Address,
    config: Configuracion,
    macs: dict[IPv4Address, str],
) -> Host:
    """Aplica a un objetivo las técnicas que operan de una en una."""
    host = Host(direccion=direccion)

    # El resultado del barrido ARP, si se practicó, ya está disponible.
    if direccion in macs:
        host.activo = True
        host.mac = macs[direccion]
        host.tecnicas_respondidas.append(TecnicaDescubrimiento.ARP)

    for tecnica in config.tecnicas_descubrimiento:
        if tecnica is TecnicaDescubrimiento.ARP:
            continue  # resuelto en el barrido previo
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
        else:  # pragma: no cover - el enumerado no admite otros valores
            continue

        if activo:
            host.activo = True
            host.tecnicas_respondidas.append(tecnica)
            # El tiempo de vida solo se conserva la primera vez que se observa:
            # todas las técnicas miden el mismo valor del mismo objetivo. ARP no
            # lo proporciona, por operar por debajo de la capa de red.
            if host.ttl_observado is None and ttl is not None:
                host.ttl_observado = ttl

    return host


def descubrir(objetivos: Sequence[IPv4Address], config: Configuracion) -> list[Host]:
    """Fase de descubrimiento. Devuelve un ``Host`` por objetivo, activo o no."""
    tecnicas = config.tecnicas_descubrimiento
    if not tecnicas:
        registro.warning("no se ha seleccionado ninguna técnica de descubrimiento")
        return [Host(direccion=d) for d in objetivos]

    macs: dict[IPv4Address, str] = {}
    if TecnicaDescubrimiento.ARP in tecnicas:
        macs = arp.barrer(objetivos, config.espera_s, config.interfaz)
        registro.info("barrido ARP: %d equipos respondieron", len(macs))

    restantes = [t for t in tecnicas if t is not TecnicaDescubrimiento.ARP]
    if restantes:
        hosts = en_paralelo(
            lambda d: _sondear_host(d, config, macs), objetivos, config.trabajadores
        )
    else:
        # Solo se pidió ARP: no hace falta paralelizar nada, el barrido ya está.
        hosts = [_sondear_host(d, config, macs) for d in objetivos]

    hosts.sort(key=lambda h: int(h.direccion))

    activos = [h for h in hosts if h.activo]
    registro.info(
        "descubrimiento: %d activos de %d objetivos con %s",
        len(activos),
        len(hosts),
        ", ".join(t.value for t in tecnicas),
    )
    return hosts
