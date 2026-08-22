"""Pruebas de identificación de servicios: extracción, banner y HTTP.

Los tres módulos se ejercitan sin red mediante inyección de la función de
diálogo. La extracción heurística se somete a una tabla de banners reales
tomados de servicios habituales, para verificar tanto los aciertos como los
casos donde la aproximación mínima no distingue.
"""

from __future__ import annotations

from ipaddress import IPv4Address

import pytest

from melmapo.core.modelo import EstadoPuerto, Host, Protocolo, Puerto, TecnicaEscaneo
from melmapo.core.orquestador import Configuracion
from melmapo.fingerprint import banner, extraccion, http, identificar_host


# --------------------------------------------------------------------------
# extraccion
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    ("entrada", "nombre_esperado", "version_esperada"),
    [
        # SSH
        ("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.15", "OpenSSH", "9.6p1"),
        ("SSH-2.0-dropbear_2022.83", "dropbear", "2022.83"),
        # SMTP (ESMTP)
        ("220 mail.example.com ESMTP Postfix (Ubuntu)", "Postfix", None),
        ("220 mail ESMTP Exim 4.94 Sat, 20 Aug 2026 12:00:00 +0000", "Exim", "4.94"),
        # FTP
        ("220 (vsFTPd 3.0.3)", "vsFTPd", "3.0.3"),
        ("220 ProFTPD 1.3.7 Server ready.", "ProFTPD", "1.3.7"),
        # HTTP: cadena de cabecera Server ya extraída
        ("Apache/2.4.58 (Ubuntu)", "Apache", "2.4.58"),
        ("nginx/1.24.0", "nginx", "1.24.0"),
        ("Microsoft-IIS/10.0", "Microsoft-IIS", "10.0"),
        # MySQL/MariaDB: la versión llega como parte del saludo binario
        ("5.5.61-0ubuntu0.14.04.1", None, "5.5.61-0ubuntu0.14.04.1"),
        ("10.6.12-MariaDB-1", "MariaDB", "10.6.12-MariaDB-1"),
        # MySQL con versión de dos números y sufijo, tomada del propio saludo binario
        (">\u0000\u0000\u0000\n5.0.51a-3ubuntu5\u0000\n\u0000\u0000\u0000mqp", None, "5.0.51a-3ubuntu5"),
        # Casos que la heurística no distingue: se aceptan como limitación.
        ("", None, None),
        ("+OK POP3 server ready", None, None),
    ],
)
def test_extraccion_reconoce_banners_habituales(entrada, nombre_esperado, version_esperada):
    nombre, version = extraccion.extraer(entrada)
    assert nombre == nombre_esperado
    assert version == version_esperada


def test_extraccion_no_devuelve_nada_ante_ausencia_total_de_patron():
    """La política del proyecto: preferir la ausencia a una interpretación forzada."""
    nombre, version = extraccion.extraer("mensaje libre sin producto ni version conocidos")
    assert nombre is None
    assert version is None


# --------------------------------------------------------------------------
# banner grabbing
# --------------------------------------------------------------------------

def _dialogo_fijo(respuesta):
    def dialogo(direccion, puerto, espera_s, estimulo=None):
        return respuesta
    return dialogo


def _puerto_abierto(numero: int = 22) -> Puerto:
    return Puerto(
        numero=numero,
        protocolo=Protocolo.TCP,
        estado=EstadoPuerto.ABIERTO,
        tecnica=TecnicaEscaneo.CONNECT,
    )


def test_banner_no_envia_estimulo(monkeypatch):
    """La técnica lee al conectar; nunca escribe."""
    llamadas = []

    def dialogo(direccion, puerto, espera_s):
        llamadas.append((direccion, puerto, espera_s))
        return "SSH-2.0-OpenSSH_9.6p1"

    puerto = _puerto_abierto()
    banner.identificar_puerto("192.0.2.20", puerto, espera_s=1.0, dialogar=dialogo)

    assert llamadas == [("192.0.2.20", 22, 1.0)]
    assert puerto.servicio is not None
    assert puerto.servicio.nombre == "OpenSSH"
    assert puerto.servicio.banner_bruto == "SSH-2.0-OpenSSH_9.6p1"


def test_banner_conserva_bruto_aunque_no_extraiga(monkeypatch):
    puerto = _puerto_abierto(numero=110)
    banner.identificar_puerto(
        "192.0.2.20", puerto, espera_s=1.0,
        dialogar=lambda *_: "+OK ready",
    )
    assert puerto.servicio is not None
    assert puerto.servicio.banner_bruto == "+OK ready"
    assert puerto.servicio.nombre is None


def test_banner_deja_puerto_intacto_si_no_hay_respuesta():
    puerto = _puerto_abierto()
    banner.identificar_puerto("192.0.2.20", puerto, espera_s=1.0, dialogar=lambda *_: None)
    assert puerto.servicio is None


def test_banner_ignora_puertos_no_abiertos(monkeypatch):
    host = Host(direccion=IPv4Address("192.0.2.20"), activo=True)
    host.puertos.extend([
        Puerto(numero=22, protocolo=Protocolo.TCP,
               estado=EstadoPuerto.ABIERTO, tecnica=TecnicaEscaneo.CONNECT),
        Puerto(numero=80, protocolo=Protocolo.TCP,
               estado=EstadoPuerto.FILTRADO, tecnica=TecnicaEscaneo.CONNECT),
        Puerto(numero=443, protocolo=Protocolo.TCP,
               estado=EstadoPuerto.CERRADO, tecnica=TecnicaEscaneo.CONNECT),
    ])
    llamadas = []
    monkeypatch.setattr(
        banner, "_dialogar",
        lambda d, p, e: llamadas.append(p) or "SSH-2.0-OpenSSH_9.6p1",
    )
    config = Configuracion(
        objetivos=[IPv4Address("192.0.2.20")], puertos=[22, 80, 443], espera_s=1.0,
    )
    banner.identificar_host(host, config)
    assert llamadas == [22]


def test_banner_respeta_servicio_previamente_identificado(monkeypatch):
    """Si otra técnica ya identificó el servicio, no se sobreescribe."""
    from melmapo.core.modelo import Servicio
    host = Host(direccion=IPv4Address("192.0.2.20"), activo=True)
    puerto = _puerto_abierto()
    puerto.servicio = Servicio(nombre="ya-identificado", version="1.0")
    host.puertos.append(puerto)

    llamadas = []
    monkeypatch.setattr(banner, "_dialogar", lambda *a: llamadas.append(a) or "SSH-2.0-Otro_9.0")
    banner.identificar_host(host, Configuracion(
        objetivos=[IPv4Address("192.0.2.20")], puertos=[22], espera_s=1.0,
    ))

    assert llamadas == []
    assert puerto.servicio.nombre == "ya-identificado"


# --------------------------------------------------------------------------
# Paralelización dentro del host
# --------------------------------------------------------------------------

def test_banner_paraleliza_los_puertos_de_un_host(monkeypatch):
    """La suma de esperas de todos los puertos debe caber en menos que su suma
    secuencial. Se emula un servicio lento con time.sleep."""
    import time

    ESPERA = 0.2

    def lento(direccion, puerto, espera_s):
        time.sleep(ESPERA)
        return "SSH-2.0-OpenSSH_9.6p1"

    monkeypatch.setattr(banner, "_dialogar", lento)

    host = Host(direccion=IPv4Address("192.0.2.20"), activo=True)
    host.puertos.extend(_puerto_abierto(n) for n in (22, 80, 443, 3306, 25))
    config = Configuracion(
        objetivos=[IPv4Address("192.0.2.20")],
        puertos=[22, 80, 443, 3306, 25],
        espera_s=1.0,
        trabajadores_fingerprint=5,
    )

    inicio = time.perf_counter()
    banner.identificar_host(host, config)
    duracion = time.perf_counter() - inicio

    # Cinco puertos sondeados en paralelo tardan del orden de una espera; en
    # serie tardarían cinco. Se toma un margen holgado para no depender del
    # planificador del sistema.
    assert duracion < ESPERA * 3


def test_http_paraleliza_los_puertos_de_un_host(monkeypatch):
    import time

    ESPERA = 0.2

    def lento(direccion, puerto, espera_s, estimulo):
        time.sleep(ESPERA)
        return RESPUESTA_APACHE

    monkeypatch.setattr(http, "_dialogar", lento)

    host = Host(direccion=IPv4Address("192.0.2.20"), activo=True)
    host.puertos.extend(_puerto_abierto(n) for n in (80, 8080, 8443, 8000))
    config = Configuracion(
        objetivos=[IPv4Address("192.0.2.20")],
        puertos=[80, 8080, 8443, 8000],
        espera_s=1.0,
        trabajadores_fingerprint=4,
    )

    inicio = time.perf_counter()
    http.identificar_host(host, config)
    duracion = time.perf_counter() - inicio

    assert duracion < ESPERA * 3


def test_configuracion_valida_trabajadores_fingerprint():
    """La cota específica debe someterse a la misma validación que la general."""
    with pytest.raises(ValueError, match="fingerprint"):
        Configuracion(
            objetivos=[IPv4Address("192.0.2.20")],
            puertos=[22],
            trabajadores_fingerprint=0,
        )


# --------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------

RESPUESTA_APACHE = (
    "HTTP/1.1 200 OK\r\n"
    "Date: Sat, 20 Aug 2026 12:00:00 GMT\r\n"
    "Server: Apache/2.4.58 (Ubuntu)\r\n"
    "X-Powered-By: PHP/8.2.7\r\n"
    "Content-Type: text/html; charset=UTF-8\r\n"
    "\r\n"
    "<html>...cuerpo irrelevante...</html>"
)


def test_http_envia_sonda_get_y_extrae_del_server(monkeypatch):
    llamadas = []

    def dialogo(direccion, puerto, espera_s, estimulo):
        llamadas.append(estimulo)
        return RESPUESTA_APACHE

    puerto = _puerto_abierto(numero=80)
    http.identificar_puerto("192.0.2.20", puerto, espera_s=1.0, dialogar=dialogo)

    assert llamadas == [http.SONDA]
    assert llamadas[0].startswith(b"GET / HTTP/1.0")
    assert puerto.servicio is not None
    assert puerto.servicio.nombre == "Apache"
    assert puerto.servicio.version == "2.4.58"
    assert puerto.servicio.cabeceras["server"] == "Apache/2.4.58 (Ubuntu)"
    assert puerto.servicio.cabeceras["x-powered-by"] == "PHP/8.2.7"


def test_http_reconoce_respuesta_sin_server(monkeypatch):
    respuesta = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    puerto = _puerto_abierto(numero=8080)
    http.identificar_puerto(
        "192.0.2.20", puerto, espera_s=1.0,
        dialogar=lambda *_a: respuesta,
    )
    assert puerto.servicio is not None
    assert puerto.servicio.nombre == "http"
    assert puerto.servicio.version is None


def test_http_registra_bruto_si_la_respuesta_no_es_http(monkeypatch):
    """Un servicio no-HTTP no atribuye nombre pero preserva la evidencia."""
    puerto = _puerto_abierto(numero=22)
    http.identificar_puerto(
        "192.0.2.20", puerto, espera_s=1.0,
        dialogar=lambda *_a: "no soy HTTP en absoluto",
    )
    assert puerto.servicio is not None
    assert puerto.servicio.nombre is None
    assert puerto.servicio.banner_bruto == "no soy HTTP en absoluto"


def test_http_deja_puerto_intacto_si_no_hay_respuesta():
    puerto = _puerto_abierto(numero=80)
    http.identificar_puerto(
        "192.0.2.20", puerto, espera_s=1.0, dialogar=lambda *_a: None,
    )
    assert puerto.servicio is None


# --------------------------------------------------------------------------
# Cascada banner + HTTP
# --------------------------------------------------------------------------

def test_cascada_solo_recurre_a_http_para_puertos_sin_identificar(monkeypatch):
    """Si el banner identifica el servicio, la sonda HTTP no se envía."""
    host = Host(direccion=IPv4Address("192.0.2.20"), activo=True)
    host.puertos.extend([
        _puerto_abierto(22),   # SSH: identifica por banner
        _puerto_abierto(80),   # HTTP: silencioso al banner, responde al GET
    ])

    def falso_banner(direccion, puerto, espera_s):
        return "SSH-2.0-OpenSSH_9.6p1" if puerto == 22 else None

    llamadas_http = []

    def falso_http(direccion, puerto, espera_s, estimulo):
        llamadas_http.append(puerto)
        return RESPUESTA_APACHE

    monkeypatch.setattr(banner, "_dialogar", falso_banner)
    monkeypatch.setattr(http, "_dialogar", falso_http)

    config = Configuracion(
        objetivos=[IPv4Address("192.0.2.20")], puertos=[22, 80], espera_s=1.0,
    )
    identificar_host(host, config)

    # HTTP se pregunta solo al 80: el 22 quedó identificado por banner.
    assert llamadas_http == [80]

    servicios = {p.numero: p.servicio for p in host.puertos}
    assert servicios[22].nombre == "OpenSSH"
    assert servicios[80].nombre == "Apache"
    assert servicios[80].version == "2.4.58"
