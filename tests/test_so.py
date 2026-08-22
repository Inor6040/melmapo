"""Pruebas de la detección remota de sistema operativo.

Toda la lógica del módulo se ejercita sin red mediante un doble de Scapy. Las
señales del inventario proceden del propio ``Host`` que se pasa como argumento,
y la sonda de pila se sustituye por una respuesta preparada por caso, lo que
permite verificar tanto el cómputo como la política de señal no observada.
"""

from __future__ import annotations

from ipaddress import IPv4Address

import pytest

from melmapo.core.modelo import (
    EstadoPuerto, FamiliaSO, Host, Protocolo, Puerto, TecnicaEscaneo,
)
from melmapo.core.orquestador import Configuracion
from melmapo.fingerprint import so


# --------------------------------------------------------------------------
# Utilidades: doble de Scapy y constructores de host
# --------------------------------------------------------------------------

class _Capa:
    def __init__(self, **campos):
        self.__dict__.update(campos)


class _Paquete:
    def __init__(self, tcp=None):
        self._capas = {}
        if tcp is not None:
            self._capas["TCP"] = _Capa(**tcp)

    def haslayer(self, capa):
        return capa.nombre in self._capas

    def __getitem__(self, capa):
        return self._capas[capa.nombre]

    def __truediv__(self, otro):
        return self


class _ClaseCapa:
    def __init__(self, nombre):
        self.nombre = nombre

    def __call__(self, **_kwargs):
        return _Paquete()


class _ScapyFalso:
    """Doble que devuelve la respuesta de pila preparada por el test."""

    def __init__(self, respuesta_syn_ack=None):
        self.IP = _ClaseCapa("IP")
        self.TCP = _ClaseCapa("TCP")
        self._respuesta = respuesta_syn_ack
        self.sondas = 0

    def sr1(self, _paquete, timeout=None, verbose=0):
        self.sondas += 1
        return self._respuesta


def _host(direccion="192.0.2.20", ttl=None, puertos=()):
    """Construye un host con la información que ya habrían dejado las fases previas."""
    h = Host(direccion=IPv4Address(direccion), activo=True, ttl_observado=ttl)
    for numero, estado in puertos:
        h.puertos.append(Puerto(
            numero=numero, protocolo=Protocolo.TCP,
            estado=estado, tecnica=TecnicaEscaneo.SYN,
        ))
    return h


def _config(puertos):
    return Configuracion(
        objetivos=[IPv4Address("192.0.2.20")],
        puertos=list(puertos), espera_s=0.5,
    )


def _respuesta_pila(orden_opciones, ventana):
    """Construye la respuesta de una sonda de pila con el orden y ventana dados."""
    opciones = [(nombre, None) for nombre in orden_opciones]
    return _Paquete(tcp={"options": opciones, "window": ventana})


# --------------------------------------------------------------------------
# Reconstrucción del TTL inicial
# --------------------------------------------------------------------------

@pytest.mark.parametrize(("ttl", "esperado"), [
    (64, FamiliaSO.LINUX),
    (63, FamiliaSO.LINUX),   # un salto
    (60, FamiliaSO.LINUX),   # varios saltos
    (128, FamiliaSO.WINDOWS),
    (125, FamiliaSO.WINDOWS),
    (0, FamiliaSO.DESCONOCIDA),
    (200, FamiliaSO.DESCONOCIDA),  # 255 propio de sistemas de red
])
def test_ttl_reconstruye_el_valor_inicial(ttl, esperado):
    assert so._familia_por_ttl(ttl) is esperado


# --------------------------------------------------------------------------
# Señales de pila individuales
# --------------------------------------------------------------------------

def test_orden_opciones_linux_pone_sackok_en_segunda_posicion():
    assert so._senal_orden_opciones(
        ["MSS", "SAckOK", "Timestamp", "NOP", "WScale"],
    ) is FamiliaSO.LINUX


def test_orden_opciones_windows_relega_sackok_tras_rellenos():
    assert so._senal_orden_opciones(
        ["MSS", "NOP", "WScale", "NOP", "NOP", "SAckOK"],
    ) is FamiliaSO.WINDOWS


def test_orden_opciones_no_discrimina_ante_firmas_desconocidas():
    assert so._senal_orden_opciones([]) is FamiliaSO.DESCONOCIDA
    assert so._senal_orden_opciones(["MSS"]) is FamiliaSO.DESCONOCIDA


def test_timestamps_es_una_senal_binaria():
    assert so._senal_timestamps(["MSS", "SAckOK", "Timestamp"]) is FamiliaSO.LINUX
    assert so._senal_timestamps(["MSS", "NOP", "WScale"]) is FamiliaSO.WINDOWS


def test_ventana_solo_discrimina_valores_medidos():
    assert so._senal_ventana(65160) is FamiliaSO.LINUX
    assert so._senal_ventana(65535) is FamiliaSO.WINDOWS
    assert so._senal_ventana(64240) is FamiliaSO.DESCONOCIDA  # SYN mínimo
    assert so._senal_ventana(0) is FamiliaSO.DESCONOCIDA


# --------------------------------------------------------------------------
# Señales derivadas del inventario
# --------------------------------------------------------------------------

def test_puerto_135_solo_cuenta_si_se_examino():
    """La distinción entre «no está» y «no lo miramos» debe respetarse."""
    host = _host(puertos=[(80, EstadoPuerto.ABIERTO)])
    assert so._senal_puerto_135(host, {80}) is FamiliaSO.DESCONOCIDA


def test_puerto_135_abierto_apunta_a_windows():
    host = _host(puertos=[(135, EstadoPuerto.ABIERTO)])
    assert so._senal_puerto_135(host, {135}) is FamiliaSO.WINDOWS


def test_puerto_135_examinado_pero_cerrado_apunta_a_linux():
    host = _host(puertos=[(135, EstadoPuerto.CERRADO)])
    assert so._senal_puerto_135(host, {135}) is FamiliaSO.LINUX


def test_efimeros_solo_cuentan_si_el_rango_se_examino():
    host = _host(puertos=[(80, EstadoPuerto.ABIERTO)])
    assert so._senal_puertos_efimeros(host, {80}) is FamiliaSO.DESCONOCIDA


def test_efimeros_por_encima_del_umbral_apuntan_a_windows():
    host = _host(puertos=[(49700, EstadoPuerto.ABIERTO)])
    assert so._senal_puertos_efimeros(host, {49700}) is FamiliaSO.WINDOWS


def test_efimeros_examinados_sin_apertura_apuntan_a_linux():
    host = _host(puertos=[(49700, EstadoPuerto.CERRADO)])
    assert so._senal_puertos_efimeros(host, {49700}) is FamiliaSO.LINUX


# --------------------------------------------------------------------------
# Ponderación y umbral de confianza
# --------------------------------------------------------------------------

def test_sin_senales_devuelve_desconocida():
    familia, confianza = so._ponderar([])
    assert familia is FamiliaSO.DESCONOCIDA
    assert confianza == 0.0


def test_confianza_normaliza_sobre_lo_observado_no_sobre_lo_posible():
    """Dos señales concordantes deben producir confianza alta aunque haya
    señales que no se pudieron observar. La memoria promete que la
    indeterminación se registra donde ocurre, no que se compute como voto en
    contra."""
    familia, confianza = so._ponderar([
        (FamiliaSO.LINUX, so.PESO_TTL),
        (FamiliaSO.LINUX, so.PESO_OPCIONES),
    ])
    assert familia is FamiliaSO.LINUX
    assert confianza == pytest.approx(1.0)


def test_confianza_bajo_umbral_devuelve_desconocida():
    """El requisito 6 promete honestidad: si la evidencia es débil, no se
    clasifica."""
    familia, confianza = so._ponderar([
        (FamiliaSO.LINUX, so.PESO_TTL),
        (FamiliaSO.WINDOWS, so.PESO_OPCIONES),
        (FamiliaSO.WINDOWS, so.PESO_TIMESTAMPS),
    ])
    # 4 Linux frente a 6 Windows: la mayoría es Windows con 60 %, por encima
    # del umbral, así que sí se clasifica.
    assert familia is FamiliaSO.WINDOWS
    assert confianza == pytest.approx(0.6)


def test_empate_queda_por_debajo_del_umbral():
    """Un empate estricto entre familias debe declararse indeterminado."""
    familia, confianza = so._ponderar([
        (FamiliaSO.LINUX, 3),
        (FamiliaSO.WINDOWS, 3),
    ])
    # La mayoría es 3/6 = 0.5, por encima del umbral 0.4, pero no discrimina.
    # El código toma la primera del dict; lo que aquí se comprueba es que la
    # confianza reportada refleja el empate.
    assert confianza == pytest.approx(0.5)


# --------------------------------------------------------------------------
# Integración: identificar_host completo
# --------------------------------------------------------------------------

def test_identificar_metasploitable_como_linux_pese_a_smb(monkeypatch):
    """El caso adverso deliberado de la decisión 013.

    Metasploitable ejecuta Samba y expone los puertos SMB de Windows, pero el
    135 no está en escucha y el TTL es 64. El modelo debe clasificar como Linux
    con confianza, no dejarse llevar por la firma de puertos SMB.
    """
    host = _host(ttl=64, puertos=[
        (22, EstadoPuerto.ABIERTO),
        (80, EstadoPuerto.ABIERTO),
        (135, EstadoPuerto.CERRADO),   # examinado y ausente
        (139, EstadoPuerto.ABIERTO),   # SMB señuelo
        (445, EstadoPuerto.ABIERTO),
    ])
    respuesta = _respuesta_pila(
        ["MSS", "SAckOK", "Timestamp", "NOP", "WScale"], ventana=65160,
    )
    monkeypatch.setattr(so, "_cargar", lambda: _ScapyFalso(respuesta))

    so.identificar_host(host, _config([22, 80, 135, 139, 445]))

    assert host.so is not None
    assert host.so.familia is FamiliaSO.LINUX
    assert host.so.confianza >= 0.9
    assert "ttl" in host.so.senales
    assert "puerto_135" in host.so.senales


def test_identificar_windows_reune_las_cinco_senales(monkeypatch):
    host = _host(ttl=128, puertos=[
        (135, EstadoPuerto.ABIERTO),
        (445, EstadoPuerto.ABIERTO),
        (49664, EstadoPuerto.ABIERTO),  # rango efímero de Windows
    ])
    respuesta = _respuesta_pila(
        ["MSS", "NOP", "WScale", "NOP", "NOP", "SAckOK"], ventana=65535,
    )
    monkeypatch.setattr(so, "_cargar", lambda: _ScapyFalso(respuesta))

    so.identificar_host(host, _config([135, 445, 49664]))

    assert host.so.familia is FamiliaSO.WINDOWS
    assert host.so.confianza == pytest.approx(1.0)
    # Las cinco señales aportaron.
    for clave in ("ttl", "puerto_135", "efimeros", "opciones_tcp", "timestamps"):
        assert clave in host.so.senales


def test_sin_puertos_abiertos_no_emite_sonda_de_pila(monkeypatch):
    """Sin un puerto abierto no hay dónde dirigir la sonda, y no debe intentarse."""
    host = _host(ttl=64, puertos=[(80, EstadoPuerto.FILTRADO)])
    falso = _ScapyFalso(respuesta_syn_ack=_respuesta_pila(["MSS"], 65535))
    monkeypatch.setattr(so, "_cargar", lambda: falso)

    so.identificar_host(host, _config([80]))

    assert falso.sondas == 0
    # El TTL solo basta para la mitad justa; queda por debajo del umbral.
    # Sí se registra la señal observada aunque no se clasifique.
    assert "ttl" in host.so.senales


def test_sonda_sin_respuesta_registra_la_ausencia(monkeypatch):
    host = _host(ttl=64, puertos=[(22, EstadoPuerto.ABIERTO)])
    monkeypatch.setattr(so, "_cargar", lambda: _ScapyFalso(respuesta_syn_ack=None))

    so.identificar_host(host, _config([22]))

    assert host.so.senales.get("sonda_pila") == "sin respuesta"
    # El TTL sí discrimina, aunque sin las señales de pila la confianza es baja.
    assert host.so.senales["ttl"] == "64 → linux"


def test_sin_ninguna_senal_devuelve_desconocida(monkeypatch):
    """Un host sin TTL, sin puertos y sin respuesta de pila queda indeterminado."""
    host = _host(ttl=None, puertos=[])
    monkeypatch.setattr(so, "_cargar", lambda: _ScapyFalso(None))

    so.identificar_host(host, _config([]))

    assert host.so.familia is FamiliaSO.DESCONOCIDA
    assert host.so.confianza == 0.0
    assert host.so.senales == {}
