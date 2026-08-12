"""Pruebas del orquestador y de la comprobación de privilegios."""

from ipaddress import IPv4Address

import pytest

from melmapo.core.modelo import EstadoPuerto, Host, Puerto, TecnicaEscaneo
from melmapo.core.orquestador import Configuracion, Orquestador, en_paralelo
from melmapo.core.privilegios import SinPrivilegios, exigir_privilegios, tiene_privilegios


def _config(**kwargs) -> Configuracion:
    base = {
        "objetivos": [IPv4Address("192.168.56.20"), IPv4Address("192.168.56.30")],
        "puertos": [22, 23, 80],
    }
    base.update(kwargs)
    return Configuracion(**base)


class TestConfiguracion:
    def test_validaciones(self):
        with pytest.raises(ValueError):
            _config(trabajadores=0)
        with pytest.raises(ValueError):
            _config(espera_s=0)

    def test_parametros_para_el_resultado(self):
        p = _config(tecnica_escaneo=TecnicaEscaneo.ACK).a_parametros()
        assert p["objetivos"] == 2
        assert p["puertos"] == 3
        assert p["tecnica_escaneo"] == "ack"


class TestEjecucionParalela:
    def test_aplica_la_funcion(self):
        assert sorted(en_paralelo(lambda n: n * 2, [1, 2, 3])) == [2, 4, 6]

    def test_coleccion_vacia(self):
        assert en_paralelo(lambda n: n, []) == []

    def test_un_fallo_no_aborta_el_resto(self):
        def falla_en_dos(n):
            if n == 2:
                raise RuntimeError("fallo simulado")
            return n

        r = en_paralelo(falla_en_dos, [1, 2, 3])
        assert sorted(r) == [1, 3]


class TestOrquestador:
    def test_sin_descubrimiento_todos_activos(self):
        r = Orquestador(_config(omitir_descubrimiento=True)).ejecutar()
        assert len(r.hosts_activos()) == 2
        assert r.duracion_s is not None

    def test_encadena_las_fases(self):
        llamadas = []

        def descubrir(objetivos, config):
            llamadas.append("descubrimiento")
            return [Host(direccion=objetivos[0], activo=True),
                    Host(direccion=objetivos[1], activo=False)]

        def escanear(host, config):
            llamadas.append("escaneo")
            host.puertos.append(Puerto(22, estado=EstadoPuerto.ABIERTO))
            return host

        def identificar(host, config):
            llamadas.append("fingerprint")
            return host

        r = Orquestador(_config(), descubrir, escanear, identificar).ejecutar()

        # El escaneo y el fingerprinting se aplican solo al host activo.
        assert llamadas == ["descubrimiento", "escaneo", "fingerprint"]
        assert len(r.hosts_activos()) == 1

    def test_fingerprint_omitido_por_configuracion(self):
        llamadas = []

        def escanear(host, config):
            host.puertos.append(Puerto(22, estado=EstadoPuerto.ABIERTO))
            return host

        def identificar(host, config):
            llamadas.append("fingerprint")
            return host

        Orquestador(
            _config(omitir_descubrimiento=True, con_fingerprint=False),
            escaneo=escanear,
            fingerprint=identificar,
        ).ejecutar()
        assert llamadas == []

    def test_fingerprint_no_se_aplica_sin_puertos_abiertos(self):
        llamadas = []

        def escanear(host, config):
            host.puertos.append(Puerto(23, estado=EstadoPuerto.CERRADO))
            return host

        def identificar(host, config):
            llamadas.append("fingerprint")
            return host

        Orquestador(
            _config(omitir_descubrimiento=True),
            escaneo=escanear,
            fingerprint=identificar,
        ).ejecutar()
        assert llamadas == []


class TestPrivilegios:
    def test_devuelve_un_booleano(self):
        assert isinstance(tiene_privilegios(), bool)

    def test_aborta_sin_privilegios(self, monkeypatch):
        monkeypatch.setattr("melmapo.core.privilegios.tiene_privilegios", lambda: False)
        with pytest.raises(SinPrivilegios, match="privilegios elevados"):
            exigir_privilegios()

    def test_no_aborta_con_privilegios(self, monkeypatch):
        monkeypatch.setattr("melmapo.core.privilegios.tiene_privilegios", lambda: True)
        exigir_privilegios()
