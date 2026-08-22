"""Modelo de datos común a todos los módulos de Melmapo.

Define las entidades sobre las que operan el descubrimiento, el escaneo y el
fingerprinting, de manera que cada fase enriquezca el mismo objeto en lugar de
producir estructuras propias que después haya que reconciliar.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import Enum
from ipaddress import IPv4Address


class EstadoPuerto(str, Enum):
    """Estados posibles de un puerto.

    Los tres primeros son los que exige el enunciado. ``NO_FILTRADO`` es
    específico del ACK Scan, que no determina si un puerto está abierto sino si
    un cortafuegos con estado se interpone. ``ABIERTO_FILTRADO`` recoge la
    ambigüedad propia del escaneo UDP, en el que la ausencia de respuesta no
    permite distinguir entre un servicio que no contesta y un descarte
    silencioso; declararla explícitamente es preferible a resolverla mediante
    una suposición no justificada.
    """

    ABIERTO = "abierto"
    CERRADO = "cerrado"
    FILTRADO = "filtrado"
    NO_FILTRADO = "no filtrado"
    ABIERTO_FILTRADO = "abierto o filtrado"


class Protocolo(str, Enum):
    TCP = "tcp"
    UDP = "udp"


class TecnicaDescubrimiento(str, Enum):
    ARP = "arp"
    ICMP = "icmp"
    TCP = "tcp"
    UDP = "udp"


class TecnicaEscaneo(str, Enum):
    SYN = "syn"
    CONNECT = "connect"
    ACK = "ack"


class FamiliaSO(str, Enum):
    WINDOWS = "windows"
    LINUX = "linux"
    DESCONOCIDA = "desconocida"


@dataclass
class Servicio:
    """Servicio identificado tras un puerto abierto.

    Se conserva siempre ``banner_bruto`` además de la versión extraída. Lo exige
    el criterio de acierto de la decisión 014: la comparación con la herramienta
    de referencia se practica sobre cadenas normalizadas, y sin el original no
    sería posible auditar la normalización ni reproducir el cómputo.
    """

    nombre: str | None = None
    version: str | None = None
    banner_bruto: str | None = None
    cabeceras: dict[str, str] = field(default_factory=dict)

    def esta_identificado(self) -> bool:
        """Un servicio se considera identificado si se conoce su nombre o su versión.

        Basta cualquiera de las dos porque ambas atribuyen información al puerto
        que un sondeo posterior no aportaría: si el banner declaró la versión
        pero el patrón no supo asignarle nombre —caso de MySQL, que en el saludo
        binario declara la versión pero no una marca reconocible sin un caso
        especial—, repetir la sonda con HTTP solo produciría ruido, y de hecho
        producía una respuesta binaria mal interpretada que sustituía la
        información ya obtenida.
        """
        return self.nombre is not None or self.version is not None


@dataclass
class Puerto:
    numero: int
    protocolo: Protocolo = Protocolo.TCP
    estado: EstadoPuerto = EstadoPuerto.FILTRADO
    tecnica: TecnicaEscaneo | None = None
    servicio: Servicio | None = None
    latencia_ms: float | None = None

    def __post_init__(self) -> None:
        if not 1 <= self.numero <= 65535:
            raise ValueError(f"puerto fuera de rango: {self.numero}")

    @property
    def esta_abierto(self) -> bool:
        return self.estado is EstadoPuerto.ABIERTO


@dataclass
class InferenciaSO:
    """Resultado de la detección de sistema operativo.

    Conforme a la decisión 013, el resultado se expresa como nivel de confianza
    y no como afirmación categórica, y se conservan las señales que lo sustentan
    para poder justificar la inferencia en la memoria.
    """

    familia: FamiliaSO = FamiliaSO.DESCONOCIDA
    confianza: float = 0.0
    senales: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not 0.0 <= self.confianza <= 1.0:
            raise ValueError(f"confianza fuera del intervalo [0, 1]: {self.confianza}")


@dataclass
class Host:
    direccion: IPv4Address
    activo: bool = False
    mac: str | None = None
    fabricante: str | None = None
    tecnicas_respondidas: list[TecnicaDescubrimiento] = field(default_factory=list)
    ttl_observado: int | None = None
    puertos: list[Puerto] = field(default_factory=list)
    so: InferenciaSO | None = None

    def puertos_abiertos(self) -> list[Puerto]:
        return [p for p in self.puertos if p.esta_abierto]

    def puerto(self, numero: int, protocolo: Protocolo = Protocolo.TCP) -> Puerto | None:
        for p in self.puertos:
            if p.numero == numero and p.protocolo is protocolo:
                return p
        return None


@dataclass
class ResultadoEscaneo:
    """Resultado completo de una ejecución.

    Incluye los parámetros empleados porque el banco de pruebas exige repetir
    cada medición y comparar ejecuciones entre sí: sin constancia de con qué
    parámetros se obtuvo cada salida, los resultados no son reproducibles.
    """

    hosts: list[Host] = field(default_factory=list)
    inicio: datetime = field(default_factory=lambda: datetime.now(UTC))
    fin: datetime | None = None
    parametros: dict[str, object] = field(default_factory=dict)

    @property
    def duracion_s(self) -> float | None:
        if self.fin is None:
            return None
        return (self.fin - self.inicio).total_seconds()

    def hosts_activos(self) -> list[Host]:
        return [h for h in self.hosts if h.activo]

    def cerrar(self) -> None:
        self.fin = datetime.now(UTC)

    def a_diccionario(self) -> dict:
        """Representación serializable, base de la salida JSON de la decisión 006."""
        datos = asdict(self)
        datos["inicio"] = self.inicio.isoformat()
        datos["fin"] = self.fin.isoformat() if self.fin else None
        datos["duracion_s"] = self.duracion_s
        for h in datos["hosts"]:
            h["direccion"] = str(h["direccion"])
        return datos
