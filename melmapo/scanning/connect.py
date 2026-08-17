"""Escaneo de puertos por conexión completa (TCP Connect Scan).

Delega el establecimiento de la conexión en la pila del sistema operativo, de
modo que completa el saludo de tres vías: SYN, SYN/ACK y ACK. Es la única de las
técnicas implementadas que no requiere construir paquetes en crudo.

Ese mismo hecho tiene dos consecuencias que interesa contrastar frente al SYN
Scan en el capítulo de casos de prueba. La primera es que, al completarse la
conexión, el servicio del extremo remoto la registra, mientras que un SYN Scan
la aborta antes de que llegue a establecerse. La segunda es de coste: completar
y cerrar el saludo exige más intercambios que enviar un único segmento y
descartar la respuesta.
"""

from __future__ import annotations

import errno
import logging
import socket
import time

from ..core.modelo import EstadoPuerto, Host, Protocolo, Puerto, TecnicaEscaneo
from ..core.orquestador import Configuracion, en_paralelo

registro = logging.getLogger(__name__)


class HostInalcanzable(OSError):
    """El host no es alcanzable en la capa de red.

    Se distingue del estado *filtrado* de forma deliberada. Un puerto filtrado
    implica que el host existe y que algo descarta el tráfico dirigido a ese
    puerto; un host inalcanzable significa que no hay camino hacia él. Confundir
    ambos casos produciría un informe en el que todos los puertos de una máquina
    apagada aparecerían como filtrados, que es precisamente el tipo de falso
    positivo que la validación debe evitar.
    """


def _clasificar(error: OSError) -> EstadoPuerto:
    """Traduce el error del sistema al estado del puerto que representa."""
    codigo = error.errno

    if codigo in (errno.ECONNREFUSED,):
        # Ha llegado un segmento RST: hay host, no hay servicio escuchando.
        return EstadoPuerto.CERRADO

    if codigo in (errno.EHOSTUNREACH, errno.ENETUNREACH, errno.EHOSTDOWN):
        raise HostInalcanzable(codigo, error.strerror)

    if codigo in (errno.EACCES, errno.EPERM):
        # Algunos cortafuegos locales rechazan la salida con este código.
        return EstadoPuerto.FILTRADO

    return EstadoPuerto.FILTRADO


def escanear_puerto(
    direccion: str,
    numero: int,
    espera_s: float,
    limitador=None,
) -> Puerto:
    """Determina el estado de un puerto mediante un intento de conexión completa."""
    puerto = Puerto(numero=numero, protocolo=Protocolo.TCP, tecnica=TecnicaEscaneo.CONNECT)

    if limitador is not None:
        limitador.acquire()
    inicio = time.perf_counter()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(espera_s)
            s.connect((direccion, numero))
            puerto.estado = EstadoPuerto.ABIERTO
    except TimeoutError:
        # Sin respuesta dentro del plazo: se descarta silenciosamente.
        puerto.estado = EstadoPuerto.FILTRADO
    except OSError as exc:
        puerto.estado = _clasificar(exc)
    finally:
        puerto.latencia_ms = round((time.perf_counter() - inicio) * 1000, 2)
        if limitador is not None:
            limitador.release()

    return puerto


def escanear_host(host: Host, config: Configuracion) -> Host:
    """Escanea todos los puertos configurados sobre un host."""
    direccion = str(host.direccion)

    def tarea(numero: int) -> Puerto:
        return escanear_puerto(direccion, numero, config.espera_s, config.limitador)

    try:
        puertos = en_paralelo(tarea, config.puertos, config.trabajadores)
    except HostInalcanzable:
        registro.warning("host inalcanzable: %s", direccion)
        host.activo = False
        return host

    host.puertos.extend(sorted(puertos, key=lambda p: p.numero))
    registro.info(
        "%s: %d abiertos de %d puertos examinados",
        direccion, len(host.puertos_abiertos()), len(puertos),
    )
    return host
