"""Escaneo de puertos: conexión completa, SYN y ACK."""

from .connect import HostInalcanzable, escanear_puerto
from .connect import escanear_host as escanear_connect

__all__ = ["HostInalcanzable", "escanear_connect", "escanear_puerto"]
