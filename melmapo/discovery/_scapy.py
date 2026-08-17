"""Carga diferida de Scapy.

La importación de Scapy conlleva un coste apreciable, del orden del segundo, por
la cantidad de capas de protocolo que registra al inicializarse. Cargarla al
importar el paquete penalizaría cualquier invocación de la herramienta, incluida
la simple consulta de la ayuda. Se difiere por ello hasta el primer uso real y se
conserva en memoria para las llamadas sucesivas.
"""

from __future__ import annotations

import logging
from types import ModuleType

registro = logging.getLogger(__name__)

_scapy: ModuleType | None = None


class ScapyNoDisponible(ImportError):
    """Scapy no está instalado o no puede inicializarse."""


def cargar():
    """Devuelve el espacio de nombres de Scapy, importándolo la primera vez."""
    global _scapy
    if _scapy is not None:
        return _scapy

    try:
        # Se silencian los avisos de inicialización, que en un sistema sin
        # IPv6 configurado o sin ruta predeterminada son ruido esperable y no
        # indican problema alguno en el segmento del laboratorio.
        logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
        logging.getLogger("scapy.loading").setLevel(logging.ERROR)
        from scapy import all as scapy_all
    except ImportError as exc:  # pragma: no cover - depende del entorno
        raise ScapyNoDisponible(
            "Scapy no está disponible. Instálelo con: pip install scapy"
        ) from exc

    # La verbosidad por defecto de Scapy escribe en la salida estándar durante
    # el envío, lo que interferiría con la tabla de resultados.
    scapy_all.conf.verb = 0
    _scapy = scapy_all
    return _scapy
