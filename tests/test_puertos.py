"""Pruebas del parseo de puertos y del modelo de datos."""

import pytest

from melmapo.core.modelo import (
    EstadoPuerto,
    Host,
    InferenciaSO,
    Protocolo,
    Puerto,
    ResultadoEscaneo,
    Servicio,
)
from melmapo.core.puertos import PUERTOS_POR_DEFECTO, ErrorPuerto, parsear_puertos


class TestParseoPuertos:
    def test_suelto(self):
        assert parsear_puertos("80") == [80]

    def test_rango(self):
        assert parsear_puertos("20-25") == [20, 21, 22, 23, 24, 25]

    def test_lista(self):
        assert parsear_puertos("22,80,443") == [22, 80, 443]

    def test_mezcla_ordenada_y_sin_duplicados(self):
        assert parsear_puertos("443,20-22,80,443") == [20, 21, 22, 80, 443]

    def test_rango_abierto_por_la_izquierda(self):
        r = parsear_puertos("-1024")
        assert r[0] == 1 and r[-1] == 1024

    def test_rango_abierto_por_la_derecha(self):
        r = parsear_puertos("65530-")
        assert r == [65530, 65531, 65532, 65533, 65534, 65535]

    def test_guion_aislado_selecciona_todos(self):
        assert len(parsear_puertos("-")) == 65535

    @pytest.mark.parametrize("entrada", [None, "", "   "])
    def test_sin_especificacion_usa_el_conjunto_por_defecto(self, entrada):
        assert parsear_puertos(entrada) == list(PUERTOS_POR_DEFECTO)

    @pytest.mark.parametrize("entrada", ["0", "65536", "-1024000", "abc", "80-20", "1-2-3"])
    def test_entradas_no_validas(self, entrada):
        with pytest.raises(ErrorPuerto):
            parsear_puertos(entrada)


class TestConjuntoPorDefecto:
    def test_incluye_el_escenario_de_filtrado(self):
        """Los tres puertos del escenario del laboratorio deben estar presentes."""
        for p in (22, 23, 80):
            assert p in PUERTOS_POR_DEFECTO

    def test_incluye_las_senales_de_windows(self):
        """El puerto 135 discrimina frente a un Linux con Samba (decisión 013)."""
        for p in (135, 139, 445):
            assert p in PUERTOS_POR_DEFECTO

    def test_ordenado_y_sin_duplicados(self):
        assert list(PUERTOS_POR_DEFECTO) == sorted(set(PUERTOS_POR_DEFECTO))


class TestModelo:
    def test_estados_previstos(self):
        valores = {e.value for e in EstadoPuerto}
        assert valores == {
            "abierto", "cerrado", "filtrado", "no filtrado", "abierto o filtrado"
        }

    def test_puerto_fuera_de_rango(self):
        with pytest.raises(ValueError):
            Puerto(numero=0)
        with pytest.raises(ValueError):
            Puerto(numero=65536)

    def test_confianza_acotada(self):
        InferenciaSO(confianza=0.0)
        InferenciaSO(confianza=1.0)
        with pytest.raises(ValueError):
            InferenciaSO(confianza=1.5)

    def test_host_filtra_puertos_abiertos(self):
        h = Host(direccion=_ip("192.168.56.30"), activo=True, puertos=[
            Puerto(22, estado=EstadoPuerto.ABIERTO),
            Puerto(23, estado=EstadoPuerto.CERRADO),
            Puerto(80, estado=EstadoPuerto.FILTRADO),
        ])
        assert [p.numero for p in h.puertos_abiertos()] == [22]

    def test_busqueda_de_puerto_por_protocolo(self):
        h = Host(direccion=_ip("192.168.56.20"), puertos=[
            Puerto(53, protocolo=Protocolo.TCP),
            Puerto(53, protocolo=Protocolo.UDP),
        ])
        assert h.puerto(53, Protocolo.UDP).protocolo is Protocolo.UDP
        assert h.puerto(9999) is None

    def test_banner_bruto_se_conserva(self):
        """La decisión 014 exige conservar el banner original sin normalizar."""
        s = Servicio(
            nombre="OpenSSH",
            version="10.2p1",
            banner_bruto="SSH-2.0-OpenSSH_10.2p1 Ubuntu-2ubuntu3",
        )
        assert "_" in s.banner_bruto
        assert s.esta_identificado()

    def test_resultado_serializable(self):
        r = ResultadoEscaneo(hosts=[Host(direccion=_ip("192.168.56.20"), activo=True)])
        r.cerrar()
        d = r.a_diccionario()
        assert d["hosts"][0]["direccion"] == "192.168.56.20"
        assert isinstance(d["inicio"], str)
        assert d["duracion_s"] is not None

    def test_hosts_activos(self):
        r = ResultadoEscaneo(hosts=[
            Host(direccion=_ip("192.168.56.20"), activo=True),
            Host(direccion=_ip("192.168.56.21"), activo=False),
        ])
        assert len(r.hosts_activos()) == 1


def _ip(texto):
    from ipaddress import IPv4Address
    return IPv4Address(texto)
