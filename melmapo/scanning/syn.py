"""Escaneo de puertos por saludo parcial (SYN Scan).

Envía un segmento de sincronización y determina el estado del puerto a partir de
la respuesta, sin llegar a completar el saludo de tres vías. La diferencia con el
escaneo por conexión completa no está en la información obtenida —ambas técnicas
distinguen los mismos estados— sino en el coste y en el rastro: el estado del
puerto ya queda determinado por el segundo segmento, de modo que el tercero es
innecesario para los fines del escaneo.

Requiere construir los paquetes directamente y, en consecuencia, privilegios
elevados, conforme a la decisión 009. A cambio, aborta la conexión antes de que
llegue a establecerse, lo que evita que el objetivo mantenga entradas
semiabiertas ocupando espacio en sus tablas de estado.

Sobre la emisión del reinicio conviene una precisión que se documenta en el
capítulo dedicado al desarrollo. Al construirse el segmento con Scapy, la pila
del sistema operativo recibe también el SYN/ACK y, al no reconocer ninguna
conexión asociada, emite por su cuenta un reinicio. El que esta función envía se
transmite igualmente y de forma deliberada: el módulo no delega el aborto en un
comportamiento del sistema anfitrión que no controla y que varía entre
plataformas. La consecuencia asumida es que el objetivo puede observar dos
reinicios en lugar de uno.
"""

from __future__ import annotations

import logging
import time
from ipaddress import IPv4Address

from ..core.modelo import EstadoPuerto, Host, Protocolo, Puerto, TecnicaEscaneo
from ..core.orquestador import Configuracion, en_paralelo
from ..discovery._scapy import cargar

registro = logging.getLogger(__name__)

# Combinaciones de banderas TCP relevantes en la respuesta.
SYN_ACK = 0x12
RST = 0x04

# Códigos de destino inalcanzable que evidencian un mecanismo de filtrado
# interpuesto. Se distinguen de la ausencia de respuesta porque acreditan que
# algo ha rechazado el tráfico de forma explícita, en lugar de descartarlo en
# silencio; ambos casos se clasifican como filtrados, pero por motivos distintos.
CODIGOS_FILTRADO = frozenset({1, 2, 3, 9, 10, 13})


def _clasificar(scapy, respuesta) -> EstadoPuerto:
    """Traduce la respuesta obtenida al estado del puerto que representa.

    La ausencia de respuesta se resuelve en la función que la invoca, porque allí
    ``respuesta`` es ``None`` y no hay nada que clasificar.
    """
    if respuesta.haslayer(scapy.TCP):
        banderas = int(respuesta[scapy.TCP].flags)
        if banderas & SYN_ACK == SYN_ACK:
            return EstadoPuerto.ABIERTO
        if banderas & RST:
            return EstadoPuerto.CERRADO
        # Cualquier otra combinación no corresponde a una respuesta legítima a un
        # SYN. Se declara filtrada en lugar de forzar una interpretación.
        registro.debug("respuesta TCP no concluyente, banderas 0x%02x", banderas)
        return EstadoPuerto.FILTRADO

    if respuesta.haslayer(scapy.ICMP):
        icmp = respuesta[scapy.ICMP]
        if int(icmp.type) == 3 and int(icmp.code) in CODIGOS_FILTRADO:
            registro.debug("destino inalcanzable, código %d", int(icmp.code))
            return EstadoPuerto.FILTRADO

    return EstadoPuerto.FILTRADO


def _abortar_conexion(scapy, direccion: str, numero: int, respuesta) -> None:
    """Libera la conexión a medias abierta por el SYN/ACK recibido.

    Replica el comportamiento del sondeo TCP de descubrimiento. El número de
    secuencia del reinicio debe ser el de acuse del segmento recibido, y el
    puerto de origen, aquel al que el objetivo ha respondido; en otro caso el
    segmento quedaría fuera de la ventana y el objetivo lo descartaría, dejando
    la conexión semiabierta que se pretendía evitar.
    """
    try:
        scapy.send(
            scapy.IP(dst=direccion)
            / scapy.TCP(
                dport=numero,
                sport=respuesta[scapy.TCP].dport,
                seq=respuesta[scapy.TCP].ack,
                flags="R",
            ),
            verbose=0,
        )
    except OSError as exc:  # pragma: no cover - depende de la red
        registro.debug("no se pudo abortar la conexión con %s:%d: %s", direccion, numero, exc)


def escanear_puerto(
    direccion: str,
    numero: int,
    espera_s: float,
    limitador=None,
) -> Puerto:
    """Determina el estado de un puerto mediante un saludo parcial."""
    puerto = Puerto(numero=numero, protocolo=Protocolo.TCP, tecnica=TecnicaEscaneo.SYN)
    scapy = cargar()

    if limitador is not None:
        limitador.acquire()
    inicio = time.perf_counter()
    try:
        sonda = scapy.IP(dst=direccion) / scapy.TCP(dport=numero, flags="S")
        respuesta = scapy.sr1(sonda, timeout=espera_s, verbose=0)
    except OSError as exc:  # pragma: no cover - depende de la red
        registro.debug("SYN Scan hacia %s:%d: %s", direccion, numero, exc)
        puerto.latencia_ms = round((time.perf_counter() - inicio) * 1000, 2)
        return puerto
    finally:
        if limitador is not None:
            limitador.release()

    puerto.latencia_ms = round((time.perf_counter() - inicio) * 1000, 2)

    if respuesta is None:
        # Sin respuesta dentro del plazo. Es el único caso cuyo coste temporal
        # equivale al tiempo de espera completo, y de ahí que el coste de un
        # escaneo lo determine el número de puertos filtrados.
        puerto.estado = EstadoPuerto.FILTRADO
        return puerto

    puerto.estado = _clasificar(scapy, respuesta)
    if puerto.estado is EstadoPuerto.ABIERTO:
        _abortar_conexion(scapy, direccion, numero, respuesta)

    return puerto


def escanear_host(host: Host, config: Configuracion) -> Host:
    """Escanea todos los puertos configurados sobre un host."""
    direccion = str(host.direccion)

    def tarea(numero: int) -> Puerto:
        return escanear_puerto(direccion, numero, config.espera_s, config.limitador)

    puertos = en_paralelo(tarea, config.puertos, config.trabajadores)

    host.puertos.extend(sorted(puertos, key=lambda p: p.numero))
    registro.info(
        "%s: %d abiertos de %d puertos examinados",
        direccion, len(host.puertos_abiertos()), len(puertos),
    )
    return host
