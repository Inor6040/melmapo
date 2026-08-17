"""Descubrimiento de equipos mediante TCP SYN Ping.

Se envía un segmento SYN a un puerto y se interpreta cualquier respuesta como
prueba de que el equipo está activo. La particularidad de esta técnica, y lo que
la hace más robusta que el eco ICMP, es que **ambas respuestas posibles son
igualmente concluyentes**: un SYN/ACK indica que el puerto está abierto y un RST
que está cerrado, pero en los dos casos hay alguien al otro lado que ha
respondido. A efectos de descubrimiento, no interesa el estado del puerto sino la
existencia del equipo.

Frente al eco ICMP presenta la ventaja de atravesar cortafuegos que descartan ese
protocolo pero permiten el tráfico dirigido a servicios en escucha. Es también la
razón de que la elección del puerto de sondeo importe: dirigirlo a uno filtrado
produciría un falso negativo.
"""

from __future__ import annotations

import logging
from ipaddress import IPv4Address

from ._scapy import cargar

registro = logging.getLogger(__name__)

PUERTO_POR_DEFECTO = 80

# Combinaciones de banderas TCP relevantes en la respuesta.
SYN_ACK = 0x12
RST = 0x04


def sondear(
    direccion: IPv4Address,
    puerto: int = PUERTO_POR_DEFECTO,
    espera_s: float = 2.0,
    limitador=None,
) -> tuple[bool, int | None]:
    """Envía un SYN y devuelve si el equipo responde y el tiempo de vida observado."""
    scapy = cargar()

    if limitador is not None:
        limitador.acquire()
    try:
        paquete = scapy.IP(dst=str(direccion)) / scapy.TCP(dport=puerto, flags="S")
        respuesta = scapy.sr1(paquete, timeout=espera_s, verbose=0)
    except OSError as exc:  # pragma: no cover - depende de la red
        registro.debug("TCP ping hacia %s: %s", direccion, exc)
        return False, None
    finally:
        if limitador is not None:
            limitador.release()

    if respuesta is None or not respuesta.haslayer(scapy.TCP):
        return False, None

    banderas = int(respuesta[scapy.TCP].flags)
    ttl = int(respuesta[scapy.IP].ttl)

    if banderas & SYN_ACK == SYN_ACK:
        # El objetivo ha abierto una conexión a medias por nosotros. Se envía un
        # RST para que la libere de inmediato en lugar de mantenerla en espera
        # hasta que expire su temporizador.
        _abortar_conexion(scapy, direccion, puerto, respuesta)
        return True, ttl

    if banderas & RST:
        return True, ttl

    return False, None


def _abortar_conexion(scapy, direccion: IPv4Address, puerto: int, respuesta) -> None:
    """Cierra la conexión a medias abierta por el SYN/ACK recibido."""
    try:
        scapy.send(
            scapy.IP(dst=str(direccion))
            / scapy.TCP(
                dport=puerto,
                sport=respuesta[scapy.TCP].dport,
                seq=respuesta[scapy.TCP].ack,
                flags="R",
            ),
            verbose=0,
        )
    except OSError as exc:  # pragma: no cover - depende de la red
        registro.debug("no se pudo abortar la conexión con %s: %s", direccion, exc)
