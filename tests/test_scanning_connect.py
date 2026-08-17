"""Pruebas del escaneo por conexión completa y de la presentación de resultados."""

import errno
import json
import socket
import threading
from ipaddress import IPv4Address

import pytest

from melmapo.core.modelo import (
    EstadoPuerto,
    FamiliaSO,
    Host,
    InferenciaSO,
    Puerto,
    ResultadoEscaneo,
    Servicio,
    TecnicaEscaneo,
)
from melmapo.core.orquestador import Configuracion
from melmapo.output import a_json, guardar_json, tabla_consola
from melmapo.scanning.connect import (
    HostInalcanzable,
    _clasificar,
    escanear_host,
    escanear_puerto,
)


@pytest.fixture
def servicio_local():
    """Levanta un servicio en un puerto libre de la interfaz de bucle local."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 0))
    s.listen(5)
    puerto = s.getsockname()[1]

    parar = threading.Event()

    def aceptar():
        s.settimeout(0.2)
        while not parar.is_set():
            try:
                conexion, _ = s.accept()
                conexion.close()
            except (TimeoutError, OSError):
                continue

    hilo = threading.Thread(target=aceptar, daemon=True)
    hilo.start()
    yield puerto
    parar.set()
    hilo.join(timeout=1)
    s.close()


@pytest.fixture
def puerto_libre():
    """Devuelve un puerto sin servicio en escucha."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    numero = s.getsockname()[1]
    s.close()
    return numero


class TestClasificacionDeErrores:
    def test_conexion_rechazada_es_cerrado(self):
        assert _clasificar(OSError(errno.ECONNREFUSED, "rechazada")) is EstadoPuerto.CERRADO

    @pytest.mark.parametrize("codigo", [errno.EHOSTUNREACH, errno.ENETUNREACH, errno.EHOSTDOWN])
    def test_inalcanzable_no_es_filtrado(self, codigo):
        """Un host inalcanzable debe distinguirse de un puerto filtrado."""
        with pytest.raises(HostInalcanzable):
            _clasificar(OSError(codigo, "sin ruta"))

    def test_error_desconocido_es_filtrado(self):
        assert _clasificar(OSError(errno.EIO, "otro")) is EstadoPuerto.FILTRADO


class TestEscaneoDePuerto:
    def test_servicio_en_escucha_es_abierto(self, servicio_local):
        p = escanear_puerto("127.0.0.1", servicio_local, espera_s=2.0)
        assert p.estado is EstadoPuerto.ABIERTO
        assert p.tecnica is TecnicaEscaneo.CONNECT
        assert p.latencia_ms is not None

    def test_sin_servicio_es_cerrado(self, puerto_libre):
        p = escanear_puerto("127.0.0.1", puerto_libre, espera_s=2.0)
        assert p.estado is EstadoPuerto.CERRADO

    def test_registra_latencia_siempre(self, puerto_libre):
        p = escanear_puerto("127.0.0.1", puerto_libre, espera_s=1.0)
        assert p.latencia_ms >= 0

    def test_respeta_el_limitador(self, servicio_local):
        limitador = threading.Semaphore(1)
        p = escanear_puerto("127.0.0.1", servicio_local, 2.0, limitador)
        assert p.estado is EstadoPuerto.ABIERTO
        # El semáforo debe quedar liberado tras la operación.
        assert limitador.acquire(blocking=False)


class TestEscaneoDeHost:
    def test_puertos_ordenados_y_completos(self, servicio_local, puerto_libre):
        host = Host(direccion=IPv4Address("127.0.0.1"), activo=True)
        config = Configuracion(
            objetivos=[IPv4Address("127.0.0.1")],
            puertos=sorted([servicio_local, puerto_libre]),
            espera_s=2.0,
        )
        escanear_host(host, config)

        assert [p.numero for p in host.puertos] == sorted([servicio_local, puerto_libre])
        assert host.puerto(servicio_local).estado is EstadoPuerto.ABIERTO
        assert host.puerto(puerto_libre).estado is EstadoPuerto.CERRADO
        assert len(host.puertos_abiertos()) == 1


class TestSalidaJSON:
    def _resultado(self):
        host = Host(
            direccion=IPv4Address("192.168.56.30"),
            activo=True,
            ttl_observado=64,
            puertos=[
                Puerto(22, estado=EstadoPuerto.ABIERTO, tecnica=TecnicaEscaneo.CONNECT,
                       servicio=Servicio(nombre="OpenSSH", version="10.2p1",
                                         banner_bruto="SSH-2.0-OpenSSH_10.2p1 Ubuntu-2ubuntu3")),
                Puerto(23, estado=EstadoPuerto.CERRADO),
                Puerto(80, estado=EstadoPuerto.FILTRADO),
            ],
            so=InferenciaSO(familia=FamiliaSO.LINUX, confianza=0.85),
        )
        r = ResultadoEscaneo(hosts=[host], parametros={"tecnica_escaneo": "connect"})
        r.cerrar()
        return r

    def test_json_valido(self):
        d = json.loads(a_json(self._resultado()))
        assert d["hosts"][0]["direccion"] == "192.168.56.30"
        assert len(d["hosts"][0]["puertos"]) == 3

    def test_conserva_el_banner_en_bruto(self):
        """El criterio de la decisión 014 exige el banner sin normalizar."""
        d = json.loads(a_json(self._resultado()))
        banner = d["hosts"][0]["puertos"][0]["servicio"]["banner_bruto"]
        assert banner == "SSH-2.0-OpenSSH_10.2p1 Ubuntu-2ubuntu3"

    def test_incluye_parametros_y_duracion(self):
        d = json.loads(a_json(self._resultado()))
        assert d["parametros"]["tecnica_escaneo"] == "connect"
        assert d["duracion_s"] is not None

    def test_guardar_en_fichero(self, tmp_path):
        destino = guardar_json(self._resultado(), tmp_path / "sub" / "r.json")
        assert destino.exists()
        assert json.loads(destino.read_text(encoding="utf-8"))["hosts"]


class TestTablaConsola:
    def test_muestra_los_tres_estados_del_escenario(self):
        """Reproduce el escenario de filtrado del laboratorio."""
        host = Host(direccion=IPv4Address("192.168.56.30"), activo=True, puertos=[
            Puerto(22, estado=EstadoPuerto.ABIERTO),
            Puerto(23, estado=EstadoPuerto.CERRADO),
            Puerto(80, estado=EstadoPuerto.FILTRADO),
        ])
        r = ResultadoEscaneo(hosts=[host])
        r.cerrar()
        salida = tabla_consola(r)

        assert "192.168.56.30" in salida
        assert "abierto" in salida
        assert "filtrado" in salida
        # El cerrado se resume, no se enumera.
        assert "1 puertos cerrados no mostrados" in salida

    def test_sin_hosts_activos(self):
        r = ResultadoEscaneo(hosts=[Host(direccion=IPv4Address("192.168.56.99"))])
        r.cerrar()
        assert "No se ha encontrado ningún host activo" in tabla_consola(r)

    def test_muestra_el_sistema_operativo_con_confianza(self):
        host = Host(direccion=IPv4Address("192.168.56.40"), activo=True,
                    so=InferenciaSO(familia=FamiliaSO.WINDOWS, confianza=0.9),
                    puertos=[Puerto(135, estado=EstadoPuerto.ABIERTO)])
        r = ResultadoEscaneo(hosts=[host])
        r.cerrar()
        salida = tabla_consola(r)
        assert "windows" in salida
        assert "90%" in salida
