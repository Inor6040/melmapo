"""Detección de filtrado mediante segmentos ACK (ACK Scan).

Esta técnica responde a una pregunta distinta de la que responden las dos
anteriores, y la confusión entre ambas es frecuente: **no determina si un puerto
está abierto**, sino si existe un mecanismo de filtrado con estado interpuesto
entre el origen y el destino. De ahí que sus dos resultados posibles sean
``NO_FILTRADO`` y ``FILTRADO``, y que ``ABIERTO`` y ``CERRADO`` no figuren nunca
entre ellos.

El fundamento es el siguiente. Un segmento con la bandera ACK enviado de manera
aislada no pertenece a ninguna conexión activa, y la especificación del protocolo
establece que el equipo que lo reciba debe responder con un reinicio, con
independencia de que el puerto tenga o no un servicio escuchando. Recibir ese
reinicio demuestra que el segmento alcanzó la pila del objetivo, lo que permite
clasificar el puerto como no filtrado. La ausencia de respuesta, o un mensaje de
destino inalcanzable, indican que algo interceptó el tráfico antes.

De ello se sigue la utilidad de la técnica: un mecanismo de filtrado sin estado
examina cada paquete de forma independiente y deja pasar el segmento al no
ajustarse al patrón de un intento de conexión, mientras que uno con estado lo
descarta al no pertenecer a ninguna conexión conocida. El resultado del escaneo
permite distinguir cuál de los dos se encuentra interpuesto.

Emplea el mismo envío por lotes que el SYN Scan, por el motivo allí expuesto y
para que la comparación de tiempos entre ambas técnicas en el banco de pruebas no
quede condicionada por una diferencia de implementación ajena a la técnica.

Nota para el banco de pruebas: la inferencia descansa sobre la ausencia de
respuesta, de modo que un cortafuegos configurado para rechazar el tráfico
devolviendo un mensaje de destino inalcanzable produce una observación distinta
de otro que lo descarte en silencio. Solo el descarte silencioso reproduce el
escenario para el que la técnica fue concebida.
"""

from __future__ import annotations

import logging
import random
import time

from ..core.modelo import EstadoPuerto, Host, Protocolo, Puerto, TecnicaEscaneo
from ..core.orquestador import Configuracion
from ..discovery._scapy import cargar
from .syn import CODIGOS_FILTRADO, LOTE, ORIGEN_MAX, ORIGEN_MIN, RST

registro = logging.getLogger(__name__)


def _clasificar(scapy, respuesta) -> EstadoPuerto:
    """Traduce la respuesta obtenida al estado de filtrado que representa."""
    if respuesta.haslayer(scapy.TCP):
        banderas = int(respuesta[scapy.TCP].flags)
        if banderas & RST:
            # El segmento alcanzó la pila del objetivo: nada lo interceptó.
            return EstadoPuerto.NO_FILTRADO
        registro.debug("respuesta TCP sin reinicio, banderas 0x%02x", banderas)
        return EstadoPuerto.FILTRADO

    if respuesta.haslayer(scapy.ICMP):
        icmp = respuesta[scapy.ICMP]
        if int(icmp.type) == 3 and int(icmp.code) in CODIGOS_FILTRADO:
            registro.debug("filtrado con rechazo explícito, código %d", int(icmp.code))
            return EstadoPuerto.FILTRADO

    return EstadoPuerto.FILTRADO


def _escanear_tanda(scapy, direccion: str, numeros: list[int], espera_s: float) -> list[Puerto]:
    """Despacha una tanda completa de segmentos ACK y recoge las respuestas."""
    origen = random.randint(ORIGEN_MIN, ORIGEN_MAX)  # noqa: S311 - no es uso criptográfico
    sondas = [
        scapy.IP(dst=direccion) / scapy.TCP(sport=origen, dport=n, flags="A")
        for n in numeros
    ]

    inicio = time.perf_counter()
    try:
        respondieron, _ = scapy.sr(sondas, timeout=espera_s, verbose=0, retry=0)
    except OSError as exc:  # pragma: no cover - depende de la red
        registro.warning("ACK Scan hacia %s fallido: %s", direccion, exc)
        return [
            Puerto(
                numero=n,
                protocolo=Protocolo.TCP,
                estado=EstadoPuerto.FILTRADO,
                tecnica=TecnicaEscaneo.ACK,
            )
            for n in numeros
        ]
    transcurrido = round((time.perf_counter() - inicio) * 1000, 2)

    estados: dict[int, EstadoPuerto] = {}
    for enviado, recibido in respondieron:
        estados[int(enviado[scapy.TCP].dport)] = _clasificar(scapy, recibido)

    return [
        Puerto(
            numero=n,
            protocolo=Protocolo.TCP,
            # Descarte silencioso: es el resultado que evidencia filtrado con estado.
            estado=estados.get(n, EstadoPuerto.FILTRADO),
            tecnica=TecnicaEscaneo.ACK,
            latencia_ms=transcurrido,
        )
        for n in numeros
    ]


def escanear_puertos(direccion: str, numeros: list[int], espera_s: float = 2.0) -> list[Puerto]:
    """Determina si un conjunto de puertos está filtrado."""
    if not numeros:
        return []

    scapy = cargar()
    puertos: list[Puerto] = []
    for inicio in range(0, len(numeros), LOTE):
        tanda = list(numeros[inicio : inicio + LOTE])
        puertos.extend(_escanear_tanda(scapy, direccion, tanda, espera_s))
    return puertos


def escanear_puerto(direccion: str, numero: int, espera_s: float = 2.0) -> Puerto:
    """Sondea un único puerto. Se ofrece por simetría con las demás técnicas."""
    return escanear_puertos(direccion, [numero], espera_s)[0]


def escanear_host(host: Host, config: Configuracion) -> Host:
    """Aplica la detección de filtrado a todos los puertos configurados."""
    direccion = str(host.direccion)
    puertos = escanear_puertos(direccion, list(config.puertos), config.espera_s)

    host.puertos.extend(sorted(puertos, key=lambda p: p.numero))
    no_filtrados = sum(1 for p in puertos if p.estado is EstadoPuerto.NO_FILTRADO)
    registro.info(
        "%s: %d no filtrados de %d puertos examinados",
        direccion, no_filtrados, len(puertos),
    )
    return host
