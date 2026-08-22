"""Identificación de servicios web mediante cabeceras HTTP.

Constituye el requisito 5 del enunciado y complementa al módulo de banner
grabbing. HTTP no emite un mensaje de bienvenida al establecerse la conexión, lo
que impide identificarlo con la técnica del apartado 3.4.2 sin un estímulo
mínimo. La técnica es sencilla: se envía una petición elemental y se examina el
juego de cabeceras que devuelve el servidor.

La particularidad de este caso, señalada en el apartado 3.4.2, es que la
declaración del producto no es un añadido de la implementación sino un campo
previsto por el propio protocolo —la cabecera ``Server``—, lo que la hace
considerablemente más regular que un banner. Con frecuencia aparece también la
cabecera ``X-Powered-By``, no normalizada pero adoptada por buena parte de los
intérpretes de páginas dinámicas.

Este módulo no aborda HTTPS. La técnica es idéntica sobre un socket envuelto en
TLS, pero exige la infraestructura de verificación de certificados que un
pentesting interno rara vez tiene resuelta y que se aparta del argumento que
sostiene el trabajo. La limitación se declara explícitamente en la decisión
formal correspondiente y se recoge en el capítulo séptimo como línea futura.
"""

from __future__ import annotations

import logging
from typing import Callable

from ..core.modelo import EstadoPuerto, Host, Puerto, Servicio
from ..core.orquestador import Configuracion, en_paralelo
from . import extraccion
from .red import dialogar as _dialogar

registro = logging.getLogger(__name__)

# Petición mínima que garantiza recibir cabeceras completas de cualquier
# servidor conforme. Se emplea HTTP/1.0 y no 1.1 deliberadamente: 1.0 no exige
# la cabecera ``Host``, con lo que la sonda no depende del nombre virtual bajo
# el que esté publicada la aplicación —dato que el operador puede no conocer— y
# la respuesta llega igual. El propósito es identificar, no navegar.
SONDA = b"GET / HTTP/1.0\r\n\r\n"


def _dividir(respuesta: str) -> tuple[str, dict[str, str]]:
    """Separa la línea de estado y las cabeceras del cuerpo de la respuesta.

    Devuelve la línea de estado y un diccionario de cabeceras con las claves
    normalizadas a minúsculas, forma en que el propio protocolo declara que
    deben tratarse como insensibles a mayúsculas y minúsculas. El cuerpo se
    descarta: no contiene información útil para la identificación del servidor.
    """
    cabecera, _, _ = respuesta.partition("\r\n\r\n")
    lineas = cabecera.splitlines()
    if not lineas:
        return "", {}

    estado = lineas[0]
    cabeceras: dict[str, str] = {}
    for linea in lineas[1:]:
        clave, sep, valor = linea.partition(":")
        if sep:
            cabeceras[clave.strip().lower()] = valor.strip()
    return estado, cabeceras


def identificar_puerto(
    direccion: str,
    puerto: Puerto,
    espera_s: float,
    dialogar: Callable[[str, int, float, bytes | None], str | None] = _dialogar,
) -> None:
    """Rellena ``puerto.servicio`` con la información devuelta por HTTP.

    Se aplica solo si el puerto está abierto y no ha sido identificado ya por
    banner. La ausencia de una cabecera ``Server`` no impide registrar el
    servicio: se conserva la respuesta como banner y las cabeceras completas,
    porque acreditan al menos que se trata de un servicio HTTP.
    """
    respuesta = dialogar(direccion, puerto.numero, espera_s, SONDA)
    if respuesta is None:
        return

    estado, cabeceras = _dividir(respuesta)
    if not estado.upper().startswith("HTTP/"):
        # La respuesta no es HTTP: probablemente el módulo de banner obtuvo aquí
        # el saludo específico de otro protocolo y su servicio ya estaba
        # registrado. La respuesta a esta sonda es basura desde el punto de
        # vista del servicio real —el ejemplo típico es MySQL, que ante un GET
        # devuelve un fragmento binario acompañado de «Bad handshake»—, de modo
        # que sobreescribir aquí el servicio previo sería perder información. Se
        # registra solo si no había nada.
        if puerto.servicio is None:
            puerto.servicio = Servicio(banner_bruto=respuesta)
        return

    server = cabeceras.get("server", "")
    nombre, version = extraccion.extraer(server) if server else (None, None)

    puerto.servicio = Servicio(
        nombre=nombre or ("http" if not server else None),
        version=version,
        banner_bruto=respuesta[:1024],  # cabeceras y algo del cuerpo, por si acaso
        cabeceras=cabeceras,
    )
    registro.debug(
        "http en %s:%d: server=%r nombre=%r versión=%r",
        direccion, puerto.numero, server, nombre, version,
    )


def identificar_host(host: Host, config: Configuracion) -> Host:
    """Aplica la técnica HTTP a todos los puertos abiertos sin identificar.

    A diferencia del banner grabbing, aquí sí se sondea aunque el puerto no
    parezca ser HTTP: la política del proyecto es no listar puertos «típicos» de
    cada servicio —un HTTP en el 8080, el 8000 o el 3000 durante una auditoría
    interna quedaría fuera— y dejar que el estímulo elemental resuelva por sí
    solo. El coste de un estímulo perdido en un puerto que no habla HTTP es
    despreciable en un pentesting interno.

    Los puertos pendientes se sondean en paralelo con la cota específica del
    fingerprint, por el mismo motivo que en el banner grabbing.
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
