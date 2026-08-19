"""Descubrimiento de equipos mediante ARP Ping.

Es la técnica más fiable de las cuatro dentro de un segmento de red local, y
también la más limitada. Ambas propiedades tienen el mismo origen: opera en la
capa de enlace.

Su fiabilidad procede de que ARP no es opcional. Un equipo que ignore las
solicitudes de eco ICMP y descarte todo el tráfico TCP entrante sigue estando
obligado a responder a una petición ARP, porque sin ella no podría comunicarse
con nadie de su propia red. No existe la figura del «cortafuegos que filtra ARP»
en el sentido en que existe para IP: los cortafuegos habituales operan en la capa
de red y superiores, de modo que no ven este tráfico.

Su limitación es la contraria: al no encaminarse fuera del dominio de difusión,
la técnica solo alcanza equipos del propio segmento. Para un pentesting interno,
que es el alcance del trabajo conforme a la decisión 003, esa restricción no
supone impedimento alguno.

Aporta además un dato que ninguna otra técnica proporciona: la dirección física
del objetivo.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from ipaddress import IPv4Address

from ._scapy import cargar

registro = logging.getLogger(__name__)

DIFUSION = "ff:ff:ff:ff:ff:ff"

# Tamaño de lote. El barrido se envía de una vez, pero fraccionarlo evita
# construir una lista de decenas de miles de paquetes en memoria cuando el
# objetivo es un segmento amplio.
LOTE = 256


def _resolver_interfaz(scapy, direccion: IPv4Address, interfaz: str | None) -> str | None:
    """Determina por qué interfaz debe salir la difusión ARP.

    Es una precisión necesaria y no un detalle de comodidad. A diferencia del
    tráfico IP, que la pila encamina por sí sola, una difusión en capa de enlace
    se emite por una interfaz concreta y no alcanza más segmento que el suyo. En
    un equipo con varios adaptadores —el caso de la máquina atacante, que dispone
    de uno para el laboratorio y otro para instalar dependencias— emitirla por el
    adaptador equivocado produce un barrido sin respuestas que resulta
    indistinguible de un segmento vacío.

    La interfaz se deduce consultando la tabla de encaminamiento para la
    dirección de destino, que es la misma decisión que tomaría el sistema al
    enviarle un paquete. Si el operador la indica expresamente, su elección
    prevalece.
    """
    if interfaz is not None:
        return interfaz

    try:
        elegida = scapy.conf.route.route(str(direccion))[0]
    except (OSError, IndexError, AttributeError):  # pragma: no cover - depende del sistema
        registro.debug("no se pudo determinar la interfaz para %s", direccion)
        return None

    registro.debug("interfaz para %s: %s", direccion, elegida)
    return elegida


def barrer(
    objetivos: Sequence[IPv4Address],
    espera_s: float = 2.0,
    interfaz: str | None = None,
) -> dict[IPv4Address, str]:
    """Resuelve las direcciones físicas de un conjunto de objetivos.

    Devuelve un diccionario con una entrada por cada equipo que haya respondido.
    Los que no respondan sencillamente no aparecen: en ARP no existe la
    ambigüedad del silencio que sí presenta el sondeo UDP, porque un equipo del
    segmento está obligado a contestar.
    """
    if not objetivos:
        return {}

    scapy = cargar()
    # La interfaz se resuelve una sola vez: todos los objetivos de un barrido
    # pertenecen al mismo segmento, que es la condición para que ARP los alcance.
    elegida = _resolver_interfaz(scapy, objetivos[0], interfaz)
    encontrados: dict[IPv4Address, str] = {}

    for inicio in range(0, len(objetivos), LOTE):
        tanda = objetivos[inicio : inicio + LOTE]
        encontrados.update(_barrer_tanda(scapy, tanda, espera_s, elegida))

    if not encontrados:
        # En ARP el silencio absoluto es anómalo: cualquier equipo del segmento
        # está obligado a responder. Lo más probable es que la difusión haya
        # salido por una interfaz que no da a la red de los objetivos.
        registro.warning(
            "el barrido ARP por %s no obtuvo ninguna respuesta; "
            "compruebe que es la interfaz del segmento de los objetivos",
            elegida or "la interfaz predeterminada",
        )

    return encontrados


def _barrer_tanda(scapy, tanda, espera_s: float, interfaz: str | None) -> dict[IPv4Address, str]:
    """Envía una tanda completa y recoge después todas las respuestas.

    La diferencia con las demás técnicas es de fondo y no de detalle. Aquellas
    emplean ``sr1``, que envía una sonda y bloquea el hilo hasta obtener
    respuesta o agotar el plazo, de modo que el coste de un barrido crece con el
    número de objetivos. Aquí se emplea ``srp``, que despacha la tanda entera y
    recoge después lo que haya llegado, con lo que el coste queda determinado por
    el tiempo de espera y no por la cantidad de direcciones.
    """
    peticion = scapy.Ether(dst=DIFUSION) / scapy.ARP(pdst=[str(d) for d in tanda])

    try:
        respondieron, _ = scapy.srp(
            peticion, timeout=espera_s, verbose=0, iface=interfaz, retry=0
        )
    except OSError as exc:  # pragma: no cover - depende de la red
        registro.warning("barrido ARP fallido: %s", exc)
        return {}

    encontrados: dict[IPv4Address, str] = {}
    for _, respuesta in respondieron:
        try:
            direccion = IPv4Address(respuesta[scapy.ARP].psrc)
        except (ValueError, IndexError):  # pragma: no cover - respuesta malformada
            continue
        encontrados[direccion] = str(respuesta[scapy.ARP].hwsrc).lower()

    return encontrados


def sondear(
    direccion: IPv4Address,
    espera_s: float = 2.0,
    interfaz: str | None = None,
) -> tuple[bool, str | None]:
    """Sondea un único objetivo. Se ofrece por simetría con las demás técnicas.

    El barrido por lotes es preferible siempre que haya más de un objetivo, de
    modo que esta función solo resulta ventajosa para comprobaciones sueltas.
    """
    encontrados = barrer([direccion], espera_s, interfaz)
    mac = encontrados.get(direccion)
    return mac is not None, mac
