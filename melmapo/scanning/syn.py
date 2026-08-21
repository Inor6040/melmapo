"""Escaneo de puertos por saludo parcial (SYN Scan).

Envía un segmento de sincronización y determina el estado del puerto a partir de
la respuesta, sin llegar a completar el saludo de tres vías. La diferencia con el
escaneo por conexión completa no está en la información obtenida —ambas técnicas
distinguen los mismos estados— sino en el coste y en el rastro: el estado del
puerto ya queda determinado por el segundo segmento, de modo que el tercero es
innecesario para los fines del escaneo.

Requiere construir los paquetes directamente y, en consecuencia, privilegios
elevados, conforme a la decisión 009.

**Sobre el envío por lotes.** La primera implementación empleaba ``sr1`` desde
varios hilos, uno por puerto, siguiendo el modelo del escaneo por conexión
completa. Resultó incorrecta: ``sr1`` no es seguro entre hilos, y el envío
adicional del reinicio que aborta cada conexión abierta interfiere con las
llamadas simultáneas de los demás hilos, de modo que las respuestas se pierden y
todos los puertos aparecen filtrados. El módulo emplea por ello ``sr``, que
despacha la tanda entera y recoge después lo que haya llegado, siguiendo la misma
solución que el barrido ARP.

**Sobre la emisión del reinicio.** Al construirse el segmento con Scapy, la pila
del sistema operativo recibe también el SYN/ACK y, al no reconocer ninguna
conexión asociada, emite por su cuenta un reinicio. El que este módulo envía se
transmite igualmente y de forma deliberada: no se delega el aborto en un
comportamiento del anfitrión que no se controla y que varía entre plataformas. La
consecuencia asumida es que el objetivo observa dos reinicios, distinguibles por
el tamaño de ventana anunciado.

**Sobre el coste temporal.** Con envío por lotes, todos los puertos que no
responden agotan un único temporizador compartido en lugar de uno por puerto. El
coste de una tanda queda determinado, por tanto, por la presencia de puertos
filtrados y no por cuántos haya: una tanda íntegramente respondida concluye de
inmediato, y basta un solo puerto filtrado para que agote el plazo completo.
"""

from __future__ import annotations

import logging
import random
import time

from ..core.modelo import EstadoPuerto, Host, Protocolo, Puerto, TecnicaEscaneo
from ..core.orquestador import Configuracion
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

# Tamaño de lote. La tanda se despacha de una vez, pero fraccionarla evita
# construir decenas de miles de paquetes en memoria al examinar el rango completo
# de puertos. Es mayor que el del barrido ARP porque cada tanda cuesta un
# temporizador completo si contiene algún puerto filtrado, de modo que
# fraccionar en exceso multiplicaría el tiempo total del escaneo.
LOTE = 1024

# Intervalo del que se toma el puerto de origen. Scapy emplea por defecto el 20,
# reservado a la transferencia de datos de FTP, valor fijo que un cortafuegos con
# reglas heredadas puede tratar de manera especial y falsear así el resultado. Se
# elige uno del rango efímero, una sola vez por tanda: variarlo paquete a paquete
# impediría emparejar cada respuesta con la sonda que la provocó.
ORIGEN_MIN = 32768
ORIGEN_MAX = 60999


def _clasificar(scapy, respuesta) -> EstadoPuerto:
    """Traduce la respuesta obtenida al estado del puerto que representa."""
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


def _abortar_conexiones(scapy, direccion: str, origen: int, abiertas: list) -> None:
    """Libera de una vez todas las conexiones a medias abiertas por la tanda.

    El número de secuencia del reinicio debe ser el de acuse del segmento
    recibido; en otro caso quedaría fuera de la ventana y el objetivo lo
    descartaría, dejando la conexión semiabierta que se pretendía evitar.
    """
    if not abiertas:
        return

    reinicios = [
        scapy.IP(dst=direccion)
        / scapy.TCP(
            sport=origen,
            dport=int(r[scapy.TCP].sport),
            seq=int(r[scapy.TCP].ack),
            flags="R",
        )
        for r in abiertas
    ]
    try:
        scapy.send(reinicios, verbose=0)
    except OSError as exc:  # pragma: no cover - depende de la red
        registro.debug("no se pudieron abortar las conexiones con %s: %s", direccion, exc)


def _escanear_tanda(scapy, direccion: str, numeros: list[int], espera_s: float) -> list[Puerto]:
    """Despacha una tanda completa y recoge después todas las respuestas."""
    origen = random.randint(ORIGEN_MIN, ORIGEN_MAX)  # noqa: S311 - no es uso criptográfico
    sondas = [
        scapy.IP(dst=direccion) / scapy.TCP(sport=origen, dport=n, flags="S")
        for n in numeros
    ]

    inicio = time.perf_counter()
    try:
        respondieron, _ = scapy.sr(sondas, timeout=espera_s, verbose=0, retry=0)
    except OSError as exc:  # pragma: no cover - depende de la red
        registro.warning("SYN Scan hacia %s fallido: %s", direccion, exc)
        return [
            Puerto(numero=n, protocolo=Protocolo.TCP, tecnica=TecnicaEscaneo.SYN)
            for n in numeros
        ]
    transcurrido = round((time.perf_counter() - inicio) * 1000, 2)

    estados: dict[int, EstadoPuerto] = {}
    abiertas = []
    for enviado, recibido in respondieron:
        numero = int(enviado[scapy.TCP].dport)
        estado = _clasificar(scapy, recibido)
        estados[numero] = estado
        if estado is EstadoPuerto.ABIERTO:
            abiertas.append(recibido)

    _abortar_conexiones(scapy, direccion, origen, abiertas)

    # La latencia se atribuye a la tanda y no al puerto: con envío por lotes no
    # existe un tiempo de ida y vuelta individual que registrar.
    return [
        Puerto(
            numero=n,
            protocolo=Protocolo.TCP,
            estado=estados.get(n, EstadoPuerto.FILTRADO),
            tecnica=TecnicaEscaneo.SYN,
            latencia_ms=transcurrido,
        )
        for n in numeros
    ]


def escanear_puertos(direccion: str, numeros: list[int], espera_s: float = 2.0) -> list[Puerto]:
    """Determina el estado de un conjunto de puertos mediante saludo parcial."""
    if not numeros:
        return []

    scapy = cargar()
    puertos: list[Puerto] = []
    for inicio in range(0, len(numeros), LOTE):
        tanda = list(numeros[inicio : inicio + LOTE])
        puertos.extend(_escanear_tanda(scapy, direccion, tanda, espera_s))
    return puertos


def escanear_puerto(direccion: str, numero: int, espera_s: float = 2.0) -> Puerto:
    """Sondea un único puerto. Se ofrece por simetría con las demás técnicas."""
    return escanear_puertos(direccion, [numero], espera_s)[0]


def escanear_host(host: Host, config: Configuracion) -> Host:
    """Escanea todos los puertos configurados sobre un host.

    No emplea el semáforo de la configuración: el envío por lotes no abre un
    descriptor por puerto, de modo que la cota que aquel impone carece aquí de
    objeto. El paralelismo entre hosts lo sigue gobernando el orquestador.
    """
    direccion = str(host.direccion)
    puertos = escanear_puertos(direccion, list(config.puertos), config.espera_s)

    host.puertos.extend(sorted(puertos, key=lambda p: p.numero))
    registro.info(
        "%s: %d abiertos de %d puertos examinados",
        direccion, len(host.puertos_abiertos()), len(puertos),
    )
    return host
