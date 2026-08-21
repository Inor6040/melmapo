"""Pruebas del SYN Scan y del ACK Scan.

Ambas técnicas construyen paquetes en crudo y exigirían privilegios elevados y un
objetivo real. Para poder ejercitarlas en cualquier entorno se sustituye Scapy
por un doble que devuelve respuestas preparadas, lo que permite verificar la
parte que contiene la lógica del módulo: la traducción de una respuesta al estado
del puerto que representa, el emparejamiento de cada respuesta con su sonda y el
tratamiento de los puertos que no responden.
"""

from __future__ import annotations

from ipaddress import IPv4Address

import pytest

from melmapo.core.modelo import EstadoPuerto, Host, Protocolo, TecnicaEscaneo
from melmapo.core.orquestador import Configuracion
from melmapo.scanning import ack, syn


# --------------------------------------------------------------------------
# Doble de Scapy
# --------------------------------------------------------------------------

class _Capa:
    def __init__(self, **campos):
        self.__dict__.update(campos)


class _Paquete:
    """Paquete simulado, indexable por clase de capa como los de Scapy."""

    def __init__(self, **capas):
        self._capas = {n: _Capa(**c) for n, c in capas.items() if c is not None}

    def haslayer(self, capa) -> bool:
        return capa.nombre in self._capas

    def __getitem__(self, capa):
        return self._capas[capa.nombre]

    def __truediv__(self, otro):
        self._capas.update(otro._capas)
        return self


class _ClaseCapa:
    """Constructor de capas: ``IP(...)`` y ``TCP(...)`` devuelven un paquete."""

    def __init__(self, nombre):
        self.nombre = nombre

    def __call__(self, **campos):
        return _Paquete(**{self.nombre: campos})


def respuesta_tcp(banderas: int, sport: int, ack_: int = 1) -> _Paquete:
    return _Paquete(TCP={"flags": banderas, "sport": sport, "ack": ack_})


def respuesta_icmp(codigo: int) -> _Paquete:
    return _Paquete(ICMP={"type": 3, "code": codigo})


class _ScapyFalso:
    """Doble que responde según un diccionario de puerto a respuesta."""

    def __init__(self, respuestas: dict[int, _Paquete]):
        self.IP = _ClaseCapa("IP")
        self.TCP = _ClaseCapa("TCP")
        self.ICMP = _ClaseCapa("ICMP")
        self._respuestas = respuestas
        self.enviados: list = []
        self.tandas: list[int] = []

    def sr(self, sondas, timeout=None, verbose=0, retry=0):
        self.tandas.append(len(sondas))
        pares, sin_respuesta = [], []
        for sonda in sondas:
            numero = sonda[self.TCP].dport
            if numero in self._respuestas:
                pares.append((sonda, self._respuestas[numero]))
            else:
                sin_respuesta.append(sonda)
        return pares, sin_respuesta

    def send(self, paquetes, verbose=0):
        self.enviados.extend(paquetes if isinstance(paquetes, list) else [paquetes])


def _instalar(monkeypatch, modulo, respuestas) -> _ScapyFalso:
    falso = _ScapyFalso(respuestas)
    monkeypatch.setattr(modulo, "cargar", lambda: falso)
    return falso


# --------------------------------------------------------------------------
# SYN Scan
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    ("banderas", "esperado"),
    [
        (0x12, EstadoPuerto.ABIERTO),   # SYN/ACK
        (0x14, EstadoPuerto.CERRADO),   # RST/ACK
        (0x04, EstadoPuerto.CERRADO),   # RST a secas
        (0x10, EstadoPuerto.FILTRADO),  # ACK suelto: no concluyente
    ],
)
def test_syn_clasifica_por_banderas(monkeypatch, banderas, esperado):
    _instalar(monkeypatch, syn, {22: respuesta_tcp(banderas, sport=22)})

    puerto = syn.escanear_puerto("192.0.2.10", 22, espera_s=0.1)

    assert puerto.estado is esperado
    assert puerto.tecnica is TecnicaEscaneo.SYN
    assert puerto.protocolo is Protocolo.TCP
    assert puerto.latencia_ms is not None


def test_syn_sin_respuesta_es_filtrado(monkeypatch):
    _instalar(monkeypatch, syn, {})
    puerto = syn.escanear_puerto("192.0.2.10", 22, espera_s=0.1)
    assert puerto.estado is EstadoPuerto.FILTRADO


@pytest.mark.parametrize("codigo", sorted(syn.CODIGOS_FILTRADO))
def test_syn_inalcanzable_administrativo_es_filtrado(monkeypatch, codigo):
    _instalar(monkeypatch, syn, {22: respuesta_icmp(codigo)})
    puerto = syn.escanear_puerto("192.0.2.10", 22, espera_s=0.1)
    assert puerto.estado is EstadoPuerto.FILTRADO


def test_syn_empareja_cada_respuesta_con_su_puerto(monkeypatch):
    """Cada estado debe corresponder al puerto que lo produjo, no a otro."""
    _instalar(monkeypatch, syn, {
        22: respuesta_tcp(0x12, sport=22),   # abierto
        80: respuesta_tcp(0x14, sport=80),   # cerrado
        # 443 no responde: filtrado
    })

    puertos = syn.escanear_puertos("192.0.2.10", [22, 80, 443], espera_s=0.1)
    estados = {p.numero: p.estado for p in puertos}

    assert estados == {
        22: EstadoPuerto.ABIERTO,
        80: EstadoPuerto.CERRADO,
        443: EstadoPuerto.FILTRADO,
    }


def test_syn_aborta_solo_las_conexiones_abiertas(monkeypatch):
    """El reinicio se emite explícitamente, y únicamente donde hubo SYN/ACK."""
    falso = _instalar(monkeypatch, syn, {
        22: respuesta_tcp(0x12, sport=22),
        80: respuesta_tcp(0x14, sport=80),
    })

    syn.escanear_puertos("192.0.2.10", [22, 80, 443], espera_s=0.1)

    assert len(falso.enviados) == 1


def test_syn_no_envia_reinicios_si_no_hay_puertos_abiertos(monkeypatch):
    falso = _instalar(monkeypatch, syn, {80: respuesta_tcp(0x14, sport=80)})
    syn.escanear_puertos("192.0.2.10", [80], espera_s=0.1)
    assert falso.enviados == []


def test_syn_fracciona_en_lotes(monkeypatch):
    """Un rango amplio no debe construirse de una sola vez en memoria."""
    falso = _instalar(monkeypatch, syn, {})
    numeros = list(range(1, syn.LOTE * 2 + 51))

    puertos = syn.escanear_puertos("192.0.2.10", numeros, espera_s=0.01)

    assert len(puertos) == len(numeros)
    assert falso.tandas == [syn.LOTE, syn.LOTE, 50]


def test_syn_lista_vacia_no_carga_scapy():
    """Sin puertos que examinar no debe llegar a importarse Scapy."""
    assert syn.escanear_puertos("192.0.2.10", [], espera_s=0.1) == []


def test_syn_escanea_todos_los_puertos_del_host(monkeypatch):
    _instalar(monkeypatch, syn, {
        22: respuesta_tcp(0x12, sport=22),
        80: respuesta_tcp(0x12, sport=80),
        443: respuesta_tcp(0x12, sport=443),
    })

    host = Host(direccion=IPv4Address("192.0.2.10"), activo=True)
    config = Configuracion(
        objetivos=[IPv4Address("192.0.2.10")],
        puertos=[22, 80, 443],
        espera_s=0.1,
    )

    syn.escanear_host(host, config)

    assert [p.numero for p in host.puertos] == [22, 80, 443]
    assert len(host.puertos_abiertos()) == 3


# --------------------------------------------------------------------------
# ACK Scan
# --------------------------------------------------------------------------

def test_ack_reinicio_significa_no_filtrado(monkeypatch):
    _instalar(monkeypatch, ack, {22: respuesta_tcp(0x04, sport=22)})

    puerto = ack.escanear_puerto("192.0.2.30", 22, espera_s=0.1)

    assert puerto.estado is EstadoPuerto.NO_FILTRADO
    assert puerto.tecnica is TecnicaEscaneo.ACK


def test_ack_sin_respuesta_es_filtrado(monkeypatch):
    """El descarte silencioso es lo que evidencia un filtrado con estado."""
    _instalar(monkeypatch, ack, {})
    puerto = ack.escanear_puerto("192.0.2.30", 22, espera_s=0.1)
    assert puerto.estado is EstadoPuerto.FILTRADO


@pytest.mark.parametrize("codigo", sorted(syn.CODIGOS_FILTRADO))
def test_ack_inalcanzable_es_filtrado(monkeypatch, codigo):
    _instalar(monkeypatch, ack, {22: respuesta_icmp(codigo)})
    puerto = ack.escanear_puerto("192.0.2.30", 22, espera_s=0.1)
    assert puerto.estado is EstadoPuerto.FILTRADO


@pytest.mark.parametrize("banderas", [0x12, 0x14, 0x04, 0x10])
def test_ack_nunca_declara_abierto_ni_cerrado(monkeypatch, banderas):
    """La técnica no responde a la pregunta de si el puerto acepta conexiones."""
    _instalar(monkeypatch, ack, {22: respuesta_tcp(banderas, sport=22)})
    puerto = ack.escanear_puerto("192.0.2.30", 22, espera_s=0.1)
    assert puerto.estado in (EstadoPuerto.NO_FILTRADO, EstadoPuerto.FILTRADO)


def test_ack_no_envia_reinicios(monkeypatch):
    """A diferencia del SYN Scan, no deja conexiones que abortar."""
    falso = _instalar(monkeypatch, ack, {22: respuesta_tcp(0x04, sport=22)})
    ack.escanear_puertos("192.0.2.30", [22], espera_s=0.1)
    assert falso.enviados == []


def test_ack_distingue_filtrado_de_no_filtrado(monkeypatch):
    _instalar(monkeypatch, ack, {
        22: respuesta_tcp(0x04, sport=22),
        443: respuesta_tcp(0x04, sport=443),
        # 80 no responde: filtrado con estado
    })

    puertos = ack.escanear_puertos("192.0.2.30", [22, 80, 443], espera_s=0.1)
    estados = {p.numero: p.estado for p in puertos}

    assert estados == {
        22: EstadoPuerto.NO_FILTRADO,
        80: EstadoPuerto.FILTRADO,
        443: EstadoPuerto.NO_FILTRADO,
    }


def test_ack_escanea_todos_los_puertos_del_host(monkeypatch):
    _instalar(monkeypatch, ack, {
        22: respuesta_tcp(0x04, sport=22),
        23: respuesta_tcp(0x04, sport=23),
        80: respuesta_tcp(0x04, sport=80),
    })

    host = Host(direccion=IPv4Address("192.0.2.30"), activo=True)
    config = Configuracion(
        objetivos=[IPv4Address("192.0.2.30")],
        puertos=[22, 23, 80],
        espera_s=0.1,
    )

    ack.escanear_host(host, config)

    assert [p.numero for p in host.puertos] == [22, 23, 80]
    assert all(p.estado is EstadoPuerto.NO_FILTRADO for p in host.puertos)
