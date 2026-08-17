"""Pruebas del descubrimiento de equipos.

Las técnicas dependen de Scapy y de la red, de modo que las respuestas se
sustituyen por dobles. Lo que se verifica aquí es la interpretación: qué
respuesta significa qué, que es donde reside la lógica propia del módulo y donde
un error produciría falsos positivos o negativos en la medición.
"""

from ipaddress import IPv4Address

from melmapo.core.modelo import TecnicaDescubrimiento
from melmapo.core.orquestador import Configuracion
from melmapo.discovery import descubrir, icmp, tcp, udp
from melmapo.discovery.udp import ResultadoUDP

# --- dobles ---------------------------------------------------------------

class _Capa:
    def __init__(self, **campos):
        self.__dict__.update(campos)


class _Respuesta:
    """Sustituto de un paquete de Scapy con las capas que interesan."""

    def __init__(self, capas: dict):
        self._capas = capas

    def haslayer(self, capa):
        return capa in self._capas

    def __getitem__(self, capa):
        return self._capas[capa]


class _ScapyFalso:
    """Espacio de nombres mínimo que imita a Scapy."""

    IP = "IP"
    ICMP = "ICMP"
    TCP = "TCP"
    UDP = "UDP"

    def __init__(self, respuesta=None):
        self._respuesta = respuesta
        self.enviados = []

    def sr1(self, paquete, timeout=None, verbose=0):
        return self._respuesta

    def send(self, paquete, verbose=0):
        self.enviados.append(paquete)

    # Constructores: devuelven marcadores, no se inspeccionan.
    def __call__(self, *a, **k):
        return object()


def _constructor(nombre):
    class _C:
        def __init__(self, *a, **k):
            pass

        def __truediv__(self, otro):
            return self

        def __rtruediv__(self, otro):
            return self

    _C.__name__ = nombre
    return _C


DESTINO = IPv4Address("192.168.56.30")


# --- ICMP -----------------------------------------------------------------

class TestICMP:
    def _con(self, monkeypatch, respuesta):
        falso = _ScapyFalso(respuesta)
        for n in ("IP", "ICMP"):
            setattr(falso, n, _constructor(n))
        monkeypatch.setattr(icmp, "cargar", lambda: falso)
        return falso

    def test_respuesta_de_eco_es_activo(self, monkeypatch):
        falso = self._con(monkeypatch, None)
        falso._respuesta = _Respuesta({falso.ICMP: _Capa(type=0, code=0),
                                       falso.IP: _Capa(ttl=64)})
        activo, ttl = icmp.sondear(DESTINO, 1.0)
        assert activo is True
        assert ttl == 64

    def test_sin_respuesta_es_inactivo(self, monkeypatch):
        self._con(monkeypatch, None)
        activo, ttl = icmp.sondear(DESTINO, 0.1)
        assert activo is False
        assert ttl is None

    def test_inalcanzable_no_es_activo(self, monkeypatch):
        """Un ICMP de inalcanzable procede de un intermedio, no del objetivo."""
        falso = self._con(monkeypatch, None)
        falso._respuesta = _Respuesta({falso.ICMP: _Capa(type=3, code=13),
                                       falso.IP: _Capa(ttl=64)})
        activo, ttl = icmp.sondear(DESTINO, 1.0)
        assert activo is False
        # El tiempo de vida de un intermedio no caracteriza al objetivo.
        assert ttl is None


# --- TCP ------------------------------------------------------------------

class TestTCP:
    def _con(self, monkeypatch, banderas, ttl=128):
        falso = _ScapyFalso(None)
        falso.IP, falso.TCP = _constructor("IP"), _constructor("TCP")
        respuesta = _Respuesta({
            falso.TCP: _Capa(flags=banderas, dport=12345, ack=1),
            falso.IP: _Capa(ttl=ttl),
        })
        falso._respuesta = respuesta
        monkeypatch.setattr(tcp, "cargar", lambda: falso)
        return falso

    def test_syn_ack_es_activo(self, monkeypatch):
        self._con(monkeypatch, 0x12)
        activo, ttl = tcp.sondear(DESTINO, 80, 1.0)
        assert activo is True
        assert ttl == 128

    def test_rst_tambien_es_activo(self, monkeypatch):
        """Un puerto cerrado prueba igualmente que el equipo existe."""
        self._con(monkeypatch, 0x14, ttl=64)
        activo, ttl = tcp.sondear(DESTINO, 80, 1.0)
        assert activo is True
        assert ttl == 64

    def test_syn_ack_provoca_el_envio_de_un_rst(self, monkeypatch):
        falso = self._con(monkeypatch, 0x12)
        tcp.sondear(DESTINO, 80, 1.0)
        assert len(falso.enviados) == 1

    def test_rst_no_provoca_envio_adicional(self, monkeypatch):
        falso = self._con(monkeypatch, 0x14)
        tcp.sondear(DESTINO, 80, 1.0)
        assert falso.enviados == []

    def test_sin_respuesta_es_inactivo(self, monkeypatch):
        falso = _ScapyFalso(None)
        falso.IP, falso.TCP = _constructor("IP"), _constructor("TCP")
        monkeypatch.setattr(tcp, "cargar", lambda: falso)
        activo, _ = tcp.sondear(DESTINO, 80, 0.1)
        assert activo is False


# --- UDP ------------------------------------------------------------------

class TestUDP:
    def _con(self, monkeypatch, respuesta):
        falso = _ScapyFalso(respuesta)
        for n in ("IP", "ICMP", "UDP"):
            setattr(falso, n, _constructor(n))
        monkeypatch.setattr(udp, "cargar", lambda: falso)
        return falso

    def test_puerto_inalcanzable_es_activo(self, monkeypatch):
        falso = self._con(monkeypatch, None)
        falso._respuesta = _Respuesta({falso.ICMP: _Capa(type=3, code=3),
                                       falso.IP: _Capa(ttl=64)})
        resultado, ttl = udp.sondear(DESTINO, 40125, 1.0)
        assert resultado is ResultadoUDP.ACTIVO
        assert ttl == 64

    def test_prohibido_administrativamente_es_filtrado(self, monkeypatch):
        falso = self._con(monkeypatch, None)
        falso._respuesta = _Respuesta({falso.ICMP: _Capa(type=3, code=13),
                                       falso.IP: _Capa(ttl=64)})
        resultado, _ = udp.sondear(DESTINO, 40125, 1.0)
        assert resultado is ResultadoUDP.FILTRADO

    def test_sin_respuesta_es_indeterminado(self, monkeypatch):
        """La ausencia de respuesta no permite concluir que el equipo no exista."""
        self._con(monkeypatch, None)
        resultado, _ = udp.sondear(DESTINO, 40125, 0.1)
        assert resultado is ResultadoUDP.INDETERMINADO
        assert resultado is not ResultadoUDP.FILTRADO

    def test_respuesta_del_servicio_tambien_prueba_actividad(self, monkeypatch):
        falso = self._con(monkeypatch, None)
        falso._respuesta = _Respuesta({falso.UDP: _Capa(), falso.IP: _Capa(ttl=64)})
        resultado, _ = udp.sondear(DESTINO, 40125, 1.0)
        assert resultado is ResultadoUDP.ACTIVO


# --- Fase completa --------------------------------------------------------

class TestFaseDescubrimiento:
    def _config(self, tecnicas, **kw):
        return Configuracion(
            objetivos=[IPv4Address("192.168.56.20"), IPv4Address("192.168.56.30")],
            puertos=[22],
            tecnicas_descubrimiento=tecnicas,
            espera_s=0.1,
            **kw,
        )

    def test_registra_todas_las_tecnicas_que_responden(self, monkeypatch):
        monkeypatch.setattr(icmp, "sondear", lambda d, e, l=None: (True, 64))
        monkeypatch.setattr(tcp, "sondear", lambda d, p, e, l=None: (True, 64))
        config = self._config([TecnicaDescubrimiento.ICMP, TecnicaDescubrimiento.TCP])

        hosts = descubrir(config.objetivos, config)
        assert all(h.activo for h in hosts)
        assert hosts[0].tecnicas_respondidas == [
            TecnicaDescubrimiento.ICMP, TecnicaDescubrimiento.TCP
        ]

    def test_una_tecnica_basta_para_marcar_activo(self, monkeypatch):
        """Caso característico: el objetivo descarta ICMP pero responde a TCP."""
        monkeypatch.setattr(icmp, "sondear", lambda d, e, l=None: (False, None))
        monkeypatch.setattr(tcp, "sondear", lambda d, p, e, l=None: (True, 128))
        config = self._config([TecnicaDescubrimiento.ICMP, TecnicaDescubrimiento.TCP])

        hosts = descubrir(config.objetivos, config)
        assert all(h.activo for h in hosts)
        assert hosts[0].tecnicas_respondidas == [TecnicaDescubrimiento.TCP]
        assert hosts[0].ttl_observado == 128

    def test_ninguna_respuesta_deja_el_host_inactivo(self, monkeypatch):
        monkeypatch.setattr(icmp, "sondear", lambda d, e, l=None: (False, None))
        config = self._config([TecnicaDescubrimiento.ICMP])
        hosts = descubrir(config.objetivos, config)
        assert not any(h.activo for h in hosts)

    def test_devuelve_los_hosts_ordenados(self, monkeypatch):
        monkeypatch.setattr(icmp, "sondear", lambda d, e, l=None: (True, 64))
        config = Configuracion(
            objetivos=[IPv4Address("192.168.56.40"), IPv4Address("192.168.56.10")],
            puertos=[22], tecnicas_descubrimiento=[TecnicaDescubrimiento.ICMP],
        )
        hosts = descubrir(config.objetivos, config)
        assert [str(h.direccion) for h in hosts] == ["192.168.56.10", "192.168.56.40"]

    def test_arp_no_implementada_se_omite_sin_fallar(self, monkeypatch):
        config = self._config([TecnicaDescubrimiento.ARP])
        hosts = descubrir(config.objetivos, config)
        assert not any(h.activo for h in hosts)


# --- Registro de parámetros -----------------------------------------------

class TestParametrosRegistrados:
    """Los parámetros deben reflejar lo ejecutado y no lo configurado."""

    def test_omitir_descubrimiento_no_declara_tecnicas(self):
        config = Configuracion(
            objetivos=[IPv4Address("192.168.56.30")],
            puertos=[22],
            tecnicas_descubrimiento=[TecnicaDescubrimiento.ICMP],
            omitir_descubrimiento=True,
        )
        assert config.a_parametros()["tecnicas_descubrimiento"] == []

    def test_sin_omitir_declara_las_tecnicas(self):
        config = Configuracion(
            objetivos=[IPv4Address("192.168.56.30")],
            puertos=[22],
            tecnicas_descubrimiento=[TecnicaDescubrimiento.ICMP],
        )
        assert config.a_parametros()["tecnicas_descubrimiento"] == ["icmp"]

    def test_puertos_de_sondeo_solo_si_se_usan(self):
        config = Configuracion(
            objetivos=[IPv4Address("192.168.56.30")],
            puertos=[22],
            tecnicas_descubrimiento=[TecnicaDescubrimiento.TCP],
        )
        p = config.a_parametros()
        assert p["puerto_ping_tcp"] == 80
        assert "puerto_ping_udp" not in p
