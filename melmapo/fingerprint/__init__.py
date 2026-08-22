"""Identificación: banner grabbing, cabeceras HTTP y detección de sistema operativo."""

from __future__ import annotations

from ..core.modelo import EstadoPuerto, Host
from ..core.orquestador import Configuracion
from . import banner, http, so


def identificar_host(host: Host, config: Configuracion) -> Host:
    """Aplica en cascada las tres técnicas de identificación.

    Se ejecuta primero el banner grabbing sobre todos los puertos abiertos, a
    continuación el módulo HTTP sobre los que hayan quedado sin identificar, y
    por último la detección de sistema operativo sobre el host. El orden no es
    arbitrario: la lectura de banners no envía nada al objetivo, mientras que
    la sonda HTTP sí lo hace; empezar por la técnica silenciosa y reservar la
    que estimula para lo que no responda de otro modo es el criterio que se
    defiende en el apartado 3.4.2 de la memoria.

    La detección de sistema operativo se sitúa en último lugar porque aprovecha
    el inventario de puertos ya completado. Emite una única sonda con opciones
    completas hacia un puerto abierto, según justifica la decisión 013.
    """
    banner.identificar_host(host, config)

    # El módulo HTTP se aplica selectivamente para no repetir sondas: solo a los
    # puertos abiertos que sigan sin nombre después del banner.
    pendientes = [
        p for p in host.puertos
        if p.estado is EstadoPuerto.ABIERTO
        and (p.servicio is None or not p.servicio.esta_identificado())
    ]
    if pendientes:
        http.identificar_host(host, config)

    so.identificar_host(host, config)

    return host


__all__ = ["banner", "http", "identificar_host", "so"]
