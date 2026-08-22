"""Pruebas del descubrimiento de equipos.

Las técnicas dependen de Scapy y de la red, de modo que las respuestas se
sustituyen por dobles. Lo que se verifica aquí es la interpretación: qué
respuesta significa qué, que es donde reside la lógica propia del módulo y donde
un error produciría falsos positivos o negativos en la medición.
"""

from ipaddress import IPv4Address

from melmapo.core.modelo import TecnicaDescubrimiento
from melmapo.core.orquestador import Configuracion
from melmapo.discovery import arp, descubrir, icmp, tcp, udp
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
                                       falso.IP: _Capa(ttl=64, src=str(DESTINO))})
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
        # Se toma una dirección de intermediario coherente con la escena: la
        # puerta de enlace del segmento habitual del laboratorio.
        falso._respuesta = _Respuesta({falso.ICMP: _Capa(type=3, code=13),
                                       falso.IP: _Capa(ttl=64, src="192.168.56.1")})
        activo, ttl = icmp.sondear(DESTINO, 1.0)
        assert activo is False
        # El tiempo de vida de un intermedio no caracteriza al objetivo.
        assert ttl is None

    def test_respuesta_de_origen_distinto_se_descarta(self, monkeypatch):
        """R-41: aunque el tipo sea Echo Reply, si el origen no es el objetivo
        no puede darse el equipo por vivo. Un paquete falsificado por cualquier
        otro equipo del segmento haría lo posible por parecer legítimo."""
        falso = self._con(monkeypatch, None)
        falso._respuesta = _Respuesta({falso.ICMP: _Capa(type=0, code=0),
                                       falso.IP: _Capa(ttl=64, src="192.168.56.99")})
        activo, ttl = icmp.sondear(DESTINO, 1.0)
        assert activo is False
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

    def test_arp_marca_activo_y_registra_la_mac(self, monkeypatch):
        monkeypatch.setattr(
            arp, "barrer",
            lambda objetivos, espera, interfaz=None: {
                IPv4Address("192.168.56.20"): "00:0c:29:20:b5:39"
            },
        )
        config = self._config([TecnicaDescubrimiento.ARP])
        hosts = descubrir(config.objetivos, config)

        assert hosts[0].activo is True
        assert hosts[0].mac == "00:0c:29:20:b5:39"
        assert hosts[0].tecnicas_respondidas == [TecnicaDescubrimiento.ARP]
        # El .30 no respondió al barrido.
        assert hosts[1].activo is False

    def test_arp_no_aporta_tiempo_de_vida(self, monkeypatch):
        """ARP opera por debajo de la capa de red: no hay campo TTL."""
        monkeypatch.setattr(
            arp, "barrer",
            lambda objetivos, espera, interfaz=None: {
                IPv4Address("192.168.56.20"): "00:0c:29:20:b5:39"
            },
        )
        config = self._config([TecnicaDescubrimiento.ARP])
        hosts = descubrir(config.objetivos, config)
        assert hosts[0].ttl_observado is None

    def test_arp_se_combina_con_las_demas(self, monkeypatch):
        monkeypatch.setattr(
            arp, "barrer",
            lambda objetivos, espera, interfaz=None: {
                IPv4Address("192.168.56.20"): "00:0c:29:20:b5:39"
            },
        )
        monkeypatch.setattr(icmp, "sondear", lambda d, e, l=None: (True, 64))
        config = self._config([TecnicaDescubrimiento.ARP, TecnicaDescubrimiento.ICMP])
        hosts = descubrir(config.objetivos, config)

        assert hosts[0].tecnicas_respondidas == [
            TecnicaDescubrimiento.ARP, TecnicaDescubrimiento.ICMP
        ]
        assert hosts[0].mac is not None
        assert hosts[0].ttl_observado == 64

    def test_sin_tecnicas_no_sondea_nada(self):
        config = self._config([])
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


# --- ARP -------------------------------------------------------------------

class _Ruta:
    def __init__(self, interfaz="eth1"):
        self._interfaz = interfaz

    def route(self, destino):
        return (self._interfaz, "192.168.56.10", "0.0.0.0")


class _Conf:
    def __init__(self, interfaz="eth1"):
        self.route = _Ruta(interfaz)


class _ScapyARP:
    """Doble de Scapy para el barrido ARP, que usa srp en lugar de sr1."""

    def __init__(self, respuestas, interfaz="eth1"):
        self._respuestas = respuestas
        self.peticiones = []
        self.interfaces = []
        self.conf = _Conf(interfaz)
        self.ARP = _constructor("ARP")
        self.Ether = _constructor("Ether")

    def srp(self, peticion, timeout=None, verbose=0, iface=None, retry=0):
        self.peticiones.append(peticion)
        self.interfaces.append(iface)
        return self._respuestas, []


class _RespuestaARP:
    def __init__(self, psrc, hwsrc, clase):
        self._capa = _Capa(psrc=psrc, hwsrc=hwsrc)
        self._clase = clase

    def __getitem__(self, capa):
        return self._capa


class TestARP:
    def _con(self, monkeypatch, pares):
        clase = _constructor("ARP")
        respuestas = [(None, _RespuestaARP(ip, mac, clase)) for ip, mac in pares]
        falso = _ScapyARP(respuestas)
        falso.ARP = clase
        monkeypatch.setattr(arp, "cargar", lambda: falso)
        return falso

    def test_barrido_devuelve_las_macs(self, monkeypatch):
        self._con(monkeypatch, [
            ("192.168.56.20", "00:0C:29:20:B5:39"),
            ("192.168.56.30", "00:0c:29:01:3f:68"),
        ])
        r = arp.barrer([IPv4Address("192.168.56.20"), IPv4Address("192.168.56.30")], 1.0)

        assert len(r) == 2
        assert r[IPv4Address("192.168.56.20")] == "00:0c:29:20:b5:39"

    def test_normaliza_a_minusculas(self, monkeypatch):
        """La comparación con la tabla de referencia exige un formato único."""
        self._con(monkeypatch, [("192.168.56.20", "00:0C:29:20:B5:39")])
        r = arp.barrer([IPv4Address("192.168.56.20")], 1.0)
        assert r[IPv4Address("192.168.56.20")].islower()

    def test_los_que_no_responden_no_aparecen(self, monkeypatch):
        self._con(monkeypatch, [("192.168.56.20", "00:0c:29:20:b5:39")])
        objetivos = [IPv4Address(f"192.168.56.{n}") for n in (20, 21, 22)]
        r = arp.barrer(objetivos, 1.0)
        assert list(r) == [IPv4Address("192.168.56.20")]

    def test_barrido_vacio(self, monkeypatch):
        self._con(monkeypatch, [])
        assert arp.barrer([IPv4Address("192.168.56.99")], 1.0) == {}

    def test_sondeo_individual(self, monkeypatch):
        self._con(monkeypatch, [("192.168.56.20", "00:0c:29:20:b5:39")])
        activo, mac = arp.sondear(IPv4Address("192.168.56.20"), 1.0)
        assert activo is True
        assert mac == "00:0c:29:20:b5:39"

    def test_sondeo_individual_sin_respuesta(self, monkeypatch):
        self._con(monkeypatch, [])
        activo, mac = arp.sondear(IPv4Address("192.168.56.99"), 1.0)
        assert activo is False
        assert mac is None

    def test_se_fracciona_en_lotes(self, monkeypatch):
        """Un segmento amplio no debe construirse como un único paquete gigante."""
        falso = self._con(monkeypatch, [])
        objetivos = [IPv4Address(f"10.0.{a}.{b}") for a in range(3) for b in range(256)]
        arp.barrer(objetivos, 1.0)
        assert len(falso.peticiones) == 3


class TestResolucionDeInterfaz:
    """La difusión ARP no se encamina: debe salir por la interfaz correcta."""

    def _con(self, monkeypatch, interfaz_ruta="eth1"):
        falso = _ScapyARP([], interfaz_ruta)
        monkeypatch.setattr(arp, "cargar", lambda: falso)
        return falso

    def test_se_deduce_de_la_tabla_de_encaminamiento(self, monkeypatch):
        falso = self._con(monkeypatch, "eth1")
        arp.barrer([IPv4Address("192.168.56.20")], 1.0)
        assert falso.interfaces == ["eth1"]

    def test_la_indicada_por_el_operador_prevalece(self, monkeypatch):
        falso = self._con(monkeypatch, "eth1")
        arp.barrer([IPv4Address("192.168.56.20")], 1.0, interfaz="eth2")
        assert falso.interfaces == ["eth2"]

    def test_se_resuelve_una_sola_vez_por_barrido(self, monkeypatch):
        falso = self._con(monkeypatch, "eth1")
        objetivos = [IPv4Address(f"10.0.{a}.{b}") for a in range(2) for b in range(256)]
        arp.barrer(objetivos, 1.0)
        assert falso.interfaces == ["eth1", "eth1"]

    def test_barrido_sin_objetivos(self, monkeypatch):
        falso = self._con(monkeypatch)
        assert arp.barrer([], 1.0) == {}
        assert falso.peticiones == []
