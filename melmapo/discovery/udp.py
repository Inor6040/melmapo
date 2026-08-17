"""Descubrimiento de equipos mediante UDP Ping.

Es la técnica menos concluyente de las cuatro, y conviene explicar por qué antes
de describirla. UDP carece de saludo: un datagrama dirigido a un puerto abierto no
genera ninguna respuesta obligatoria, de modo que la técnica no busca una
contestación del servicio sino un mensaje ICMP de puerto inalcanzable emitido por
la pila del objetivo. Ese mensaje prueba que el equipo está activo, y por eso el
datagrama se dirige deliberadamente a un puerto que con toda probabilidad esté
cerrado.

De ahí se sigue una asimetría que atraviesa toda la técnica: **la respuesta es
concluyente, pero su ausencia no lo es**. No recibir nada puede significar que el
equipo no existe, que un cortafuegos descarta el datagrama, que descarta el
mensaje ICMP de vuelta, o que el puerto elegido resultó estar abierto y el
servicio no contestó. Con la información disponible esos casos son
indistinguibles.

La herramienta no resuelve esa ambigüedad mediante una suposición: la declara. El
resultado del sondeo distingue entre confirmación positiva, negación fundada
—cuando llega un ICMP que prueba que el objetivo es alcanzable pero está
filtrado— e indeterminación.
"""

from __future__ import annotations

import logging
from enum import Enum
from ipaddress import IPv4Address

from ._scapy import cargar

registro = logging.getLogger(__name__)

# Puerto de sondeo. Se elige uno alto sin asignación habitual para maximizar la
# probabilidad de que esté cerrado y la pila responda con el mensaje esperado.
PUERTO_POR_DEFECTO = 40125

DESTINO_INALCANZABLE = 3
PUERTO_INALCANZABLE = 3
CODIGOS_FILTRADO = {1, 2, 9, 10, 13}


class ResultadoUDP(str, Enum):
    """Resultado de un sondeo UDP.

    ``INDETERMINADO`` no equivale a equipo inactivo: significa que la prueba no
    permite pronunciarse. Distinguirlo de ``INACTIVO`` es lo que evita contar
    como falso negativo un resultado que la técnica nunca pudo determinar.
    """

    ACTIVO = "activo"
    FILTRADO = "filtrado"
    INDETERMINADO = "indeterminado"


def sondear(
    direccion: IPv4Address,
    puerto: int = PUERTO_POR_DEFECTO,
    espera_s: float = 2.0,
    limitador=None,
) -> tuple[ResultadoUDP, int | None]:
    """Envía un datagrama y clasifica la respuesta."""
    scapy = cargar()

    if limitador is not None:
        limitador.acquire()
    try:
        paquete = scapy.IP(dst=str(direccion)) / scapy.UDP(dport=puerto)
        respuesta = scapy.sr1(paquete, timeout=espera_s, verbose=0)
    except OSError as exc:  # pragma: no cover - depende de la red
        registro.debug("UDP ping hacia %s: %s", direccion, exc)
        return ResultadoUDP.INDETERMINADO, None
    finally:
        if limitador is not None:
            limitador.release()

    if respuesta is None:
        return ResultadoUDP.INDETERMINADO, None

    # Un servicio que sí contesta al datagrama también prueba la existencia del
    # equipo, aunque no sea la respuesta que la técnica busca.
    if respuesta.haslayer(scapy.UDP):
        return ResultadoUDP.ACTIVO, int(respuesta[scapy.IP].ttl)

    if not respuesta.haslayer(scapy.ICMP):
        return ResultadoUDP.INDETERMINADO, None

    tipo = int(respuesta[scapy.ICMP].type)
    codigo = int(respuesta[scapy.ICMP].code)

    if tipo == DESTINO_INALCANZABLE:
        if codigo == PUERTO_INALCANZABLE:
            # El objetivo ha respondido por sí mismo: está activo y el puerto
            # cerrado, que es exactamente lo que la técnica busca.
            return ResultadoUDP.ACTIVO, int(respuesta[scapy.IP].ttl)
        if codigo in CODIGOS_FILTRADO:
            # Procede de un dispositivo intermedio, no del objetivo. Prueba que
            # hay filtrado, no que el equipo exista.
            registro.debug("UDP hacia %s filtrado, código %d", direccion, codigo)
            return ResultadoUDP.FILTRADO, None

    return ResultadoUDP.INDETERMINADO, None
