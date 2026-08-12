"""Pruebas del parseo de objetivos."""

from ipaddress import IPv4Address

import pytest

from melmapo.core.objetivos import ErrorObjetivo, parsear_objetivos


class TestDireccionSuelta:
    def test_una_direccion(self):
        assert parsear_objetivos("192.168.56.20") == [IPv4Address("192.168.56.20")]

    def test_espacios_alrededor(self):
        assert parsear_objetivos("  192.168.56.20  ") == [IPv4Address("192.168.56.20")]


class TestCIDR:
    def test_veinticuatro_excluye_red_y_difusion(self):
        r = parsear_objetivos("192.168.56.0/24")
        assert len(r) == 254
        assert r[0] == IPv4Address("192.168.56.1")
        assert r[-1] == IPv4Address("192.168.56.254")

    def test_treinta_y_dos_devuelve_la_propia_direccion(self):
        assert parsear_objetivos("192.168.56.20/32") == [IPv4Address("192.168.56.20")]

    def test_no_estricto_admite_bits_de_host(self):
        assert len(parsear_objetivos("192.168.56.20/24")) == 254

    def test_prefijo_demasiado_amplio(self):
        with pytest.raises(ErrorObjetivo, match="demasiado amplio"):
            parsear_objetivos("10.0.0.0/8")


class TestRango:
    def test_abreviado_sobre_ultimo_octeto(self):
        r = parsear_objetivos("192.168.56.10-20")
        assert len(r) == 11
        assert r[0] == IPv4Address("192.168.56.10")
        assert r[-1] == IPv4Address("192.168.56.20")

    def test_entre_direcciones_completas(self):
        r = parsear_objetivos("192.168.56.10-192.168.56.12")
        assert r == [IPv4Address(f"192.168.56.{n}") for n in (10, 11, 12)]

    def test_cruza_frontera_de_octeto(self):
        r = parsear_objetivos("192.168.55.254-192.168.56.1")
        assert len(r) == 4

    def test_extremos_iguales(self):
        assert parsear_objetivos("192.168.56.10-10") == [IPv4Address("192.168.56.10")]

    def test_invertido(self):
        with pytest.raises(ErrorObjetivo, match="invertido"):
            parsear_objetivos("192.168.56.20-10")

    def test_octeto_fuera_de_rango(self):
        with pytest.raises(ErrorObjetivo, match="fuera de rango"):
            parsear_objetivos("192.168.56.10-300")


class TestLista:
    def test_direcciones_sueltas(self):
        r = parsear_objetivos("192.168.56.20,192.168.56.30,192.168.56.40")
        assert len(r) == 3

    def test_formas_mezcladas(self):
        r = parsear_objetivos("192.168.56.10,192.168.56.20-22,192.168.56.40/32")
        assert r == [IPv4Address(f"192.168.56.{n}") for n in (10, 20, 21, 22, 40)]

    def test_elimina_duplicados_y_ordena(self):
        r = parsear_objetivos("192.168.56.30,192.168.56.10,192.168.56.30")
        assert r == [IPv4Address("192.168.56.10"), IPv4Address("192.168.56.30")]

    def test_comas_sobrantes(self):
        assert len(parsear_objetivos("192.168.56.10,,192.168.56.20,")) == 2


class TestEntradasNoValidas:
    @pytest.mark.parametrize("entrada", ["", "   ", ",", ",,"])
    def test_vacias(self, entrada):
        with pytest.raises(ErrorObjetivo):
            parsear_objetivos(entrada)

    @pytest.mark.parametrize(
        "entrada",
        ["no-es-una-ip", "192.168.56.999", "192.168.56", "192.168.56.10-20-30", "::1"],
    )
    def test_mal_formadas(self, entrada):
        with pytest.raises(ErrorObjetivo):
            parsear_objetivos(entrada)


class TestLaboratorio:
    """El segmento del laboratorio debe interpretarse correctamente.

    El barrido completo ha de incluir la dirección .1, que corresponde al
    adaptador virtual del anfitrión: es un host legítimo del segmento y su
    omisión convertiría un acierto del descubrimiento en un falso positivo.
    """

    def test_segmento_completo_incluye_el_anfitrion(self):
        r = parsear_objetivos("192.168.56.0/24")
        assert IPv4Address("192.168.56.1") in r
        for ultimo in (10, 20, 30, 40):
            assert IPv4Address(f"192.168.56.{ultimo}") in r

    def test_solo_los_objetivos(self):
        r = parsear_objetivos("192.168.56.20,192.168.56.30,192.168.56.40")
        assert IPv4Address("192.168.56.10") not in r
