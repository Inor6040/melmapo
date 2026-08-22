"""Coordinación de las fases de una ejecución.

El orquestador encadena descubrimiento, escaneo y fingerprinting sobre un mismo
``ResultadoEscaneo``, de modo que cada fase enriquece el resultado de la
anterior. Las fases se reciben por inyección: el núcleo no importa los módulos
que las implementan, lo que permite ejercitarlas por separado en el banco de
pruebas y sustituirlas por dobles en las pruebas unitarias.

Concentra además la ejecución concurrente, conforme a la decisión 006b, que fija
un único modelo basado en `ThreadPoolExecutor` para todas las técnicas.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable, Iterable, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from ipaddress import IPv4Address
from typing import Protocol, TypeVar

from .modelo import (
    Host,
    Protocolo,
    ResultadoEscaneo,
    TecnicaDescubrimiento,
    TecnicaEscaneo,
)

registro = logging.getLogger(__name__)

T = TypeVar("T")
R = TypeVar("R")

TRABAJADORES_POR_DEFECTO = 50
TRABAJADORES_FINGERPRINT_POR_DEFECTO = 10
ESPERA_POR_DEFECTO_S = 2.0


@dataclass
class Configuracion:
    objetivos: list[IPv4Address]
    puertos: list[int] = field(default_factory=list)
    protocolo: Protocolo = Protocolo.TCP
    tecnicas_descubrimiento: list[TecnicaDescubrimiento] = field(default_factory=list)
    tecnica_escaneo: TecnicaEscaneo = TecnicaEscaneo.SYN
    trabajadores: int = TRABAJADORES_POR_DEFECTO
    trabajadores_fingerprint: int = TRABAJADORES_FINGERPRINT_POR_DEFECTO
    espera_s: float = ESPERA_POR_DEFECTO_S
    interfaz: str | None = None
    omitir_descubrimiento: bool = False
    con_fingerprint: bool = True
    puerto_ping_tcp: int = 80
    puerto_ping_udp: int = 40125
    _limitador: threading.Semaphore | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self.trabajadores < 1:
            raise ValueError("el número de trabajadores debe ser al menos 1")
        if self.trabajadores_fingerprint < 1:
            raise ValueError("el número de trabajadores de fingerprint debe ser al menos 1")
        if self.espera_s <= 0:
            raise ValueError("el tiempo de espera debe ser positivo")
        if self._limitador is None:
            self._limitador = threading.Semaphore(self.trabajadores)

    @property
    def limitador(self) -> threading.Semaphore:
        """Semáforo que acota el número total de operaciones de red simultáneas.

        La paralelización se produce en dos niveles: el orquestador reparte los
        hosts entre hilos y cada fase reparte a su vez los puertos de un mismo
        host. Sin una cota común, ambos niveles se multiplicarían y una
        configuración de cincuenta trabajadores abriría dos mil quinientos
        sockets a la vez, agotando descriptores y falseando las mediciones de
        tiempo por saturación de la pila. El semáforo se adquiere únicamente
        alrededor de la operación de red, nunca mientras un hilo espera a otro,
        de modo que no puede producirse un interbloqueo entre ambos niveles.
        """
        assert self._limitador is not None  # garantizado por __post_init__
        return self._limitador

    def a_parametros(self) -> dict[str, object]:
        """Parámetros de la ejecución, para dejar constancia en el resultado.

        Se registra lo que efectivamente se ejecuta y no lo que se configuró. La
        distinción importa cuando se omite el descubrimiento: declarar las
        técnicas seleccionadas cuando la fase no llegó a ejecutarse induciría a
        error a quien leyera después el fichero en crudo del anexo, y el
        apartado dedicado a la metodología de medición promete que las salidas
        permiten reproducir el cómputo.
        """
        ejecutadas = (
            [] if self.omitir_descubrimiento
            else [t.value for t in self.tecnicas_descubrimiento]
        )
        parametros: dict[str, object] = {
            "objetivos": len(self.objetivos),
            "puertos": len(self.puertos),
            "protocolo": self.protocolo.value,
            "tecnicas_descubrimiento": ejecutadas,
            "tecnica_escaneo": self.tecnica_escaneo.value,
            "trabajadores": self.trabajadores,
            "trabajadores_fingerprint": self.trabajadores_fingerprint,
            "espera_s": self.espera_s,
            "omitir_descubrimiento": self.omitir_descubrimiento,
        }
        if TecnicaDescubrimiento.TCP.value in ejecutadas:
            parametros["puerto_ping_tcp"] = self.puerto_ping_tcp
        if TecnicaDescubrimiento.UDP.value in ejecutadas:
            parametros["puerto_ping_udp"] = self.puerto_ping_udp
        return parametros


class FaseDescubrimiento(Protocol):
    def __call__(self, objetivos: Sequence[IPv4Address], config: Configuracion) -> list[Host]: ...


class FaseEscaneo(Protocol):
    def __call__(self, host: Host, config: Configuracion) -> Host: ...


class FaseFingerprint(Protocol):
    def __call__(self, host: Host, config: Configuracion) -> Host: ...


def en_paralelo(
    funcion: Callable[[T], R],
    elementos: Iterable[T],
    trabajadores: int = TRABAJADORES_POR_DEFECTO,
) -> list[R]:
    """Aplica una función sobre una colección con un número acotado de hilos.

    Los fallos individuales se registran y se descartan en lugar de propagarse:
    en un escaneo, que un objetivo falle no debe interrumpir el resto. La
    incidencia queda en el registro para poder auditarla después.
    """
    elementos = list(elementos)
    if not elementos:
        return []

    resultados: list[R] = []
    with ThreadPoolExecutor(max_workers=min(trabajadores, len(elementos))) as ejecutor:
        for elemento, resultado in zip(elementos, ejecutor.map(_envolver(funcion), elementos)):
            if resultado is _FALLO:
                continue
            resultados.append(resultado)  # type: ignore[arg-type]
    return resultados


_FALLO = object()


def _envolver(funcion: Callable[[T], R]) -> Callable[[T], R | object]:
    def interno(elemento: T) -> R | object:
        try:
            return funcion(elemento)
        except Exception:  # noqa: BLE001 - un fallo aislado no debe abortar el escaneo
            registro.exception("fallo al procesar %r", elemento)
            return _FALLO

    return interno


class Orquestador:
    def __init__(
        self,
        config: Configuracion,
        descubrimiento: FaseDescubrimiento | None = None,
        escaneo: FaseEscaneo | None = None,
        fingerprint: FaseFingerprint | None = None,
    ) -> None:
        self.config = config
        self._descubrimiento = descubrimiento
        self._escaneo = escaneo
        self._fingerprint = fingerprint

    def ejecutar(self) -> ResultadoEscaneo:
        resultado = ResultadoEscaneo(parametros=self.config.a_parametros())

        resultado.hosts = self._fase_descubrimiento()
        activos = resultado.hosts_activos()
        registro.info("hosts activos: %d de %d", len(activos), len(resultado.hosts))

        if activos and self._escaneo is not None:
            self._fase_escaneo(activos)

        if activos and self.config.con_fingerprint and self._fingerprint is not None:
            self._fase_fingerprint(activos)

        resultado.cerrar()
        return resultado

    def _fase_descubrimiento(self) -> list[Host]:
        if self.config.omitir_descubrimiento or self._descubrimiento is None:
            # Sin descubrimiento se asume que todos los objetivos están activos.
            # Es el comportamiento correcto cuando el operador ya sabe que lo
            # están y quiere evitar el coste de una fase que no aporta nada.
            return [Host(direccion=d, activo=True) for d in self.config.objetivos]
        return self._descubrimiento(self.config.objetivos, self.config)

    def _fase_escaneo(self, activos: list[Host]) -> None:
        en_paralelo(
            lambda h: self._escaneo(h, self.config),  # type: ignore[misc]
            activos,
            self.config.trabajadores,
        )

    def _fase_fingerprint(self, activos: list[Host]) -> None:
        con_puertos = [h for h in activos if h.puertos_abiertos()]
        en_paralelo(
            lambda h: self._fingerprint(h, self.config),  # type: ignore[misc]
            con_puertos,
            self.config.trabajadores,
        )
