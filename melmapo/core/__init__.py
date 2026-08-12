"""Núcleo: modelo de datos, parseo de entradas, privilegios y orquestación."""

from .modelo import (
    EstadoPuerto,
    FamiliaSO,
    Host,
    InferenciaSO,
    Protocolo,
    Puerto,
    ResultadoEscaneo,
    Servicio,
    TecnicaDescubrimiento,
    TecnicaEscaneo,
)
from .objetivos import ErrorObjetivo, parsear_objetivos
from .orquestador import Configuracion, Orquestador, en_paralelo
from .privilegios import SinPrivilegios, exigir_privilegios, tiene_privilegios
from .puertos import PUERTOS_POR_DEFECTO, ErrorPuerto, parsear_puertos

__all__ = [
    "PUERTOS_POR_DEFECTO",
    "Configuracion",
    "ErrorObjetivo",
    "ErrorPuerto",
    "EstadoPuerto",
    "FamiliaSO",
    "Host",
    "InferenciaSO",
    "Orquestador",
    "Protocolo",
    "Puerto",
    "ResultadoEscaneo",
    "Servicio",
    "SinPrivilegios",
    "TecnicaDescubrimiento",
    "TecnicaEscaneo",
    "en_paralelo",
    "exigir_privilegios",
    "parsear_objetivos",
    "parsear_puertos",
    "tiene_privilegios",
]
