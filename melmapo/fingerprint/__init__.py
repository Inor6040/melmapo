"""Identificación de servicios: banner grabbing y cabeceras HTTP."""

from __future__ import annotations

from ..core.modelo import EstadoPuerto, Host
from ..core.orquestador import Configuracion
from . import banner, http


def identificar_host(host: Host, config: Configuracion) -> Host:
    """Aplica en cascada las técnicas de identificación de servicios.

    Se ejecuta primero el banner grabbing sobre todos los puertos abiertos y a
    continuación el módulo HTTP sobre los que hayan quedado sin identificar. El
    orden no es arbitrario: la lectura de banners no envía nada al objetivo,
    mientras que la sonda HTTP sí lo hace; empezar por la técnica silenciosa y
    reservar la que estimula para lo que no responda de otro modo es el criterio
    que se defiende en el apartado 3.4.2 de la memoria.
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

    return host


__all__ = ["banner", "http", "identificar_host"]
