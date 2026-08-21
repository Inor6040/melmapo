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

Nota para el banco de pruebas: la inferencia descansa sobre la ausencia de
respuesta, de modo que un cortafuegos configurado para rechazar el tráfico
devolviendo un mensaje de destino inalcanzable produce una observación distinta
de otro que lo descarte en silencio. Solo el descarte silencioso reproduce el
escenario para el que la técnica fue concebida.
"""

from __future__ import annotations

import logging
import time

from ..core.modelo import EstadoPuerto, Host, Protocolo, Puerto, TecnicaEscaneo
from ..core.orquestador import Configuracion, en_paralelo
from ..discovery._scapy import cargar
from .syn import CODIGOS_FILTRADO, RST

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


def escanear_puerto(
    direccion: str,
    numero: int,
    espera_s: float,
    limitador=None,
) -> Puerto:
    """Determina si un puerto está filtrado mediante un segmento ACK aislado."""
    puerto = Puerto(
        numero=numero,
        protocolo=Protocolo.TCP,
        estado=EstadoPuerto.FILTRADO,
        tecnica=TecnicaEscaneo.ACK,
    )
    scapy = cargar()

    if limitador is not None:
        limitador.acquire()
    inicio = time.perf_counter()
    try:
        sonda = scapy.IP(dst=direccion) / scapy.TCP(dport=numero, flags="A")
        respuesta = scapy.sr1(sonda, timeout=espera_s, verbose=0)
    except OSError as exc:  # pragma: no cover - depende de la red
        registro.debug("ACK Scan hacia %s:%d: %s", direccion, numero, exc)
        puerto.latencia_ms = round((time.perf_counter() - inicio) * 1000, 2)
        return puerto
    finally:
        if limitador is not None:
            limitador.release()

    puerto.latencia_ms = round((time.perf_counter() - inicio) * 1000, 2)

    if respuesta is None:
        # Descarte silencioso: es el resultado que evidencia filtrado con estado.
        puerto.estado = EstadoPuerto.FILTRADO
        return puerto

    puerto.estado = _clasificar(scapy, respuesta)
    return puerto


def escanear_host(host: Host, config: Configuracion) -> Host:
    """Aplica la detección de filtrado a todos los puertos configurados."""
    direccion = str(host.direccion)

    def tarea(numero: int) -> Puerto:
        return escanear_puerto(direccion, numero, config.espera_s, config.limitador)

    puertos = en_paralelo(tarea, config.puertos, config.trabajadores)

    host.puertos.extend(sorted(puertos, key=lambda p: p.numero))
    no_filtrados = sum(1 for p in puertos if p.estado is EstadoPuerto.NO_FILTRADO)
    registro.info(
        "%s: %d no filtrados de %d puertos examinados",
        direccion, no_filtrados, len(puertos),
    )
    return host
