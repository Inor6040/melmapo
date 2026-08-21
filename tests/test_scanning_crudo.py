"""Pruebas del SYN Scan y del ACK Scan.

Ambas técnicas construyen paquetes en crudo y exigirían privilegios elevados y
un objetivo real. Para poder ejercitarlas en cualquier entorno se sustituye
Scapy por un doble que devuelve respuestas preparadas, lo que permite verificar
la parte que realmente contiene la lógica del módulo: la traducción de una
respuesta al estado del puerto que representa.
"""

from __future__ import annotations

from ipaddress import IPv4Address

import pytest

from melmapo.core.modelo import EstadoPuerto, Host, Protocolo, TecnicaEscaneo
from melmapo.core.orquestador import Configuracion
from melmapo.scanning import ack, syn


class _Capa:
    """Capa de un paquete simulado, con acceso por atributo."""

    def __init__(self, **campos):
        self.__dict__.update(campos)


class _Respuesta:
    """Paquete simulado, indexable por clase de capa como los de Scapy."""

    def __init__(self, tcp=None, icmp=None):
        self._capas = {}
        if tcp is not None:
            self._capas["TCP"] = _Capa(**tcp)
        if icmp is not None:
            self._capas["ICMP"] = _Capa(**icmp)

    def haslayer(self, capa) -> bool:
        return getattr(capa, "_nombre", None) in self._capas

    def __getitem__(self, capa):
        return self._capas[capa._nombre]


class _ClaseCapa:
    def __init__(self, nombre):
        self._nombre = nombre

    def __call__(self, **_kwargs):
        return self

    def __truediv__(self, otro):
        return self


class _ScapyFalso:
    """Doble de Scapy que devuelve siempre la misma respuesta preparada."""

    def __init__(self, respuesta):
        self.TCP = _ClaseCapa("TCP")
        self.ICMP = _ClaseCapa("ICMP")
        self.IP = _ClaseCapa("IP")
        self._respuesta = respuesta
        self.enviados = []

    def sr1(self, _paquete, timeout=None, verbose=0):
        return self._respuesta

    def send(self, paquete, verbose=0):
        self.enviados.append(paquete)


def _instalar(monkeypatch, modulo, respuesta) -> _ScapyFalso:
    falso = _ScapyFalso(respuesta)
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
    respuesta = _Respuesta(tcp={"flags": banderas, "dport": 40000, "ack": 1})
    _instalar(monkeypatch, syn, respuesta)

    puerto = syn.escanear_puerto("192.0.2.10", 22, espera_s=0.1)

    assert puerto.estado is esperado
    assert puerto.tecnica is TecnicaEscaneo.SYN
    assert puerto.protocolo is Protocolo.TCP
    assert puerto.latencia_ms is not None


def test_syn_sin_respuesta_es_filtrado(monkeypatch):
    _instalar(monkeypatch, syn, None)
    puerto = syn.escanear_puerto("192.0.2.10", 22, espera_s=0.1)
    assert puerto.estado is EstadoPuerto.FILTRADO


@pytest.mark.parametrize("codigo", sorted(syn.CODIGOS_FILTRADO))
def test_syn_inalcanzable_administrativo_es_filtrado(monkeypatch, codigo):
    respuesta = _Respuesta(icmp={"type": 3, "code": codigo})
    _instalar(monkeypatch, syn, respuesta)
    puerto = syn.escanear_puerto("192.0.2.10", 22, espera_s=0.1)
    assert puerto.estado is EstadoPuerto.FILTRADO


def test_syn_aborta_la_conexion_cuando_el_puerto_esta_abierto(monkeypatch):
    """El reinicio se emite explícitamente y no se delega en la pila del sistema."""
    respuesta = _Respuesta(tcp={"flags": 0x12, "dport": 40000, "ack": 7})
    falso = _instalar(monkeypatch, syn, respuesta)

    syn.escanear_puerto("192.0.2.10", 22, espera_s=0.1)

    assert len(falso.enviados) == 1


def test_syn_no_aborta_cuando_el_puerto_esta_cerrado(monkeypatch):
    respuesta = _Respuesta(tcp={"flags": 0x14, "dport": 40000, "ack": 7})
    falso = _instalar(monkeypatch, syn, respuesta)

    syn.escanear_puerto("192.0.2.10", 22, espera_s=0.1)

    assert falso.enviados == []


def test_syn_escanea_todos_los_puertos_del_host(monkeypatch):
    respuesta = _Respuesta(tcp={"flags": 0x12, "dport": 40000, "ack": 1})
    _instalar(monkeypatch, syn, respuesta)

    host = Host(direccion=IPv4Address("192.0.2.10"), activo=True)
    config = Configuracion(
        objetivos=[IPv4Address("192.0.2.10")],
        puertos=[22, 80, 443],
        espera_s=0.1,
        trabajadores=3,
    )

    syn.escanear_host(host, config)

    assert [p.numero for p in host.puertos] == [22, 80, 443]
    assert len(host.puertos_abiertos()) == 3


# --------------------------------------------------------------------------
# ACK Scan
# --------------------------------------------------------------------------

def test_ack_reinicio_significa_no_filtrado(monkeypatch):
    respuesta = _Respuesta(tcp={"flags": 0x04, "dport": 40000, "ack": 1})
    _instalar(monkeypatch, ack, respuesta)

    puerto = ack.escanear_puerto("192.0.2.30", 22, espera_s=0.1)

    assert puerto.estado is EstadoPuerto.NO_FILTRADO
    assert puerto.tecnica is TecnicaEscaneo.ACK


def test_ack_sin_respuesta_es_filtrado(monkeypatch):
    """El descarte silencioso es lo que evidencia un filtrado con estado."""
    _instalar(monkeypatch, ack, None)
    puerto = ack.escanear_puerto("192.0.2.30", 22, espera_s=0.1)
    assert puerto.estado is EstadoPuerto.FILTRADO


@pytest.mark.parametrize("codigo", sorted(syn.CODIGOS_FILTRADO))
def test_ack_inalcanzable_es_filtrado(monkeypatch, codigo):
    respuesta = _Respuesta(icmp={"type": 3, "code": codigo})
    _instalar(monkeypatch, ack, respuesta)
    puerto = ack.escanear_puerto("192.0.2.30", 22, espera_s=0.1)
    assert puerto.estado is EstadoPuerto.FILTRADO


def test_ack_nunca_declara_abierto_ni_cerrado(monkeypatch):
    """La técnica no responde a la pregunta de si el puerto acepta conexiones."""
    for banderas in (0x12, 0x14, 0x04, 0x10):
        respuesta = _Respuesta(tcp={"flags": banderas, "dport": 40000, "ack": 1})
        _instalar(monkeypatch, ack, respuesta)
        puerto = ack.escanear_puerto("192.0.2.30", 22, espera_s=0.1)
        assert puerto.estado in (EstadoPuerto.NO_FILTRADO, EstadoPuerto.FILTRADO)


def test_ack_escanea_todos_los_puertos_del_host(monkeypatch):
    respuesta = _Respuesta(tcp={"flags": 0x04, "dport": 40000, "ack": 1})
    _instalar(monkeypatch, ack, respuesta)

    host = Host(direccion=IPv4Address("192.0.2.30"), activo=True)
    config = Configuracion(
        objetivos=[IPv4Address("192.0.2.30")],
        puertos=[22, 23, 80],
        espera_s=0.1,
        trabajadores=3,
    )

    ack.escanear_host(host, config)

    assert [p.numero for p in host.puertos] == [22, 23, 80]
    assert all(p.estado is EstadoPuerto.NO_FILTRADO for p in host.puertos)
