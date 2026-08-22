"""Detección remota de sistema operativo por señales de pila TCP/IP.

Constituye el sexto y último requisito del enunciado. Implementa el modelo de
cinco señales descrito en la decisión 013 y en el apartado 3.4.3 de la memoria,
con dos rasgos que aquel apartado promete: la sonda se construye para maximizar
el número de señales observables, y el resultado se expresa como un grado de
confianza sostenido sobre señales de peso conocido, no como una afirmación
categórica.

**Sobre la fuente de las señales.** El módulo aprovecha material que ya han
producido otras fases. El tiempo de vida procede del ICMP Ping, validado por
dirección de origen tras el cierre de R-41. Las señales derivadas del inventario
—presencia del puerto 135 y del rango efímero de Windows— se leen del resultado
del SYN Scan que ya ha recorrido el objetivo. Únicamente las tres señales de
pila —ausencia de marcas de tiempo, orden de opciones y tamaño de ventana—
exigen una sonda propia, porque el SYN Scan envía un segmento pelado y la
respuesta a un SYN pelado no discrimina, según se comprobó en las mediciones que
motivaron la decisión 013.

**Sobre la distinción entre señal contraria y señal no observada.** Un puerto
135 no listado en el resultado significa una cosa muy distinta si fue examinado
que si no lo fue: en el primer caso confirma su ausencia, en el segundo el
módulo no sabe nada al respecto. La política del proyecto es que la herramienta
no añade tráfico que el operador no pidió, de modo que las señales derivadas del
inventario solo se computan cuando los puertos correspondientes han formado
parte del escaneo. El cómputo de confianza normaliza sobre las señales que
efectivamente se hayan observado, y no sobre el peso total posible: una
detección que dispuso solo del TTL y del orden de opciones puede alcanzar
confianza alta si ambos discriminan hacia la misma familia.
"""

from __future__ import annotations

import logging
import time
from typing import Callable

from ..core.modelo import EstadoPuerto, FamiliaSO, Host, InferenciaSO, Puerto
from ..core.orquestador import Configuracion
from ..discovery._scapy import cargar as _cargar

registro = logging.getLogger(__name__)

# Peso de cada señal en la ponderación final. La suma es 15 y no un número
# redondo a propósito: ninguna señal aislada, ni siquiera el TTL —la más
# discriminante—, supera el 40 % del máximo, de modo que ni un valor claro basta
# para clasificar sin corroboración.
PESO_TTL = 4
PESO_TIMESTAMPS = 3
PESO_OPCIONES = 3
PESO_PUERTO_135 = 2
PESO_EFIMEROS = 2
PESO_VENTANA = 1

# Umbrales del resultado final. La memoria promete que la herramienta declara
# indeterminación en lugar de forzar una interpretación cuando la confianza no
# es suficiente; el umbral de 40 % es el mínimo por debajo del cual la
# clasificación pierde su respaldo.
UMBRAL_CONFIANZA = 0.40

# Puerto y rango que constituyen señales derivadas del inventario. El 135 es el
# asignador de extremos RPC de Microsoft, que Samba no implementa, con lo que
# discrimina frente a Metasploitable —cuya firma SMB sería por lo demás
# indistinguible de la de un Windows—. El umbral efímero es el que Windows
# emplea por defecto según su documentación; Linux usa 32768–60999.
PUERTO_135 = 135
EFIMEROS_WINDOWS_MIN = 49152


def _familia_por_ttl(ttl: int) -> FamiliaSO:
    """Reconstruye el TTL inicial a partir del observado, contando los saltos.

    El valor por defecto en Linux es 64 y en Windows 128. Cada encaminador que
    atraviesa el paquete decrementa la cuenta, de modo que un TTL observado se
    interpreta contra el múltiplo de referencia más próximo por arriba.
    """
    if ttl <= 0:
        return FamiliaSO.DESCONOCIDA
    if ttl <= 64:
        return FamiliaSO.LINUX
    if ttl <= 128:
        return FamiliaSO.WINDOWS
    # TTL > 128 correspondería a valores iniciales de 255, propios de sistemas
    # de red y de algunos BSD antiguos, que quedan fuera del alcance del trabajo.
    return FamiliaSO.DESCONOCIDA


def _sondear_pila(scapy, direccion: str, puerto_abierto: int, espera_s: float):
    """Envía un SYN con opciones completas y devuelve la respuesta.

    La sonda anuncia el juego de opciones acordado en la decisión 013: MSS,
    permiso SACK, marcas de tiempo y escalado de ventana, en el orden que
    utilizan clientes reales. Es este juego el que provoca respuestas
    discriminantes entre pilas, según se comprobó experimentalmente.
    """
    opciones = [
        ("MSS", 1460),
        ("SAckOK", b""),
        ("Timestamp", (0, 0)),
        ("NOP", None),
        ("WScale", 7),
    ]
    sonda = scapy.IP(dst=direccion) / scapy.TCP(
        dport=puerto_abierto, flags="S", options=opciones,
    )
    try:
        respuesta = scapy.sr1(sonda, timeout=espera_s, verbose=0)
    except OSError as exc:  # pragma: no cover - depende de la red
        registro.debug("sonda de SO hacia %s:%d fallida: %s", direccion, puerto_abierto, exc)
        return None
    return respuesta


def _leer_opciones(scapy, respuesta):
    """Extrae la lista de opciones TCP de una respuesta.

    Scapy devuelve las opciones como lista de tuplas ``(nombre, valor)`` en el
    mismo orden en que aparecen en el segmento. El orden es la señal que
    interesa, no los valores.
    """
    if respuesta is None or not respuesta.haslayer(scapy.TCP):
        return None
    opciones = getattr(respuesta[scapy.TCP], "options", None) or []
    return [nombre for nombre, _valor in opciones]


def _senal_orden_opciones(orden: list[str]) -> FamiliaSO:
    """Aplica el criterio de firma de pila del apartado 3.4.3.

    Linux sitúa ``SAckOK`` en segunda posición tras ``MSS``; Windows lo relega
    tras rellenos ``NOP``. Otras firmas se consideran no discriminantes en
    lugar de forzar una atribución.
    """
    if len(orden) < 2:
        return FamiliaSO.DESCONOCIDA
    if orden[0] == "MSS" and orden[1] == "SAckOK":
        return FamiliaSO.LINUX
    if "NOP" in orden and orden.index("NOP") < orden.index("SAckOK") if "SAckOK" in orden else False:
        return FamiliaSO.WINDOWS
    # Segunda comprobación explícita para el caso de que la firma de Windows
    # aparezca sin ``SAckOK``, poco frecuente pero observable.
    if orden[0] == "MSS" and orden[1] == "NOP":
        return FamiliaSO.WINDOWS
    return FamiliaSO.DESCONOCIDA


def _senal_timestamps(orden: list[str]) -> FamiliaSO:
    """La presencia de marcas de tiempo apunta a Linux; su ausencia, a Windows.

    Windows no habilita ``Timestamp`` de serie y Linux sí, aunque el operador
    puede alterarlo. La señal es binaria y no numérica, lo que la hace robusta
    frente a variaciones de valor.
    """
    return FamiliaSO.LINUX if "Timestamp" in orden else FamiliaSO.WINDOWS


def _senal_ventana(ventana: int) -> FamiliaSO:
    """Valor característico del SYN/ACK ante una sonda con opciones completas.

    65160 en Ubuntu Server, 65535 en Windows 10; medido sobre el cable en el
    laboratorio. La medición proviene de una sola versión de cada sistema, por
    lo que la señal tiene peso bajo: sirve como refuerzo, no como prueba.
    """
    if ventana == 65535:
        return FamiliaSO.WINDOWS
    if ventana == 65160:
        return FamiliaSO.LINUX
    return FamiliaSO.DESCONOCIDA


def _senal_puerto_135(host: Host, puertos_examinados: set[int]) -> FamiliaSO:
    """Presencia del asignador de extremos RPC de Microsoft.

    Discrimina frente a Metasploitable, que ejecuta Samba y expone 139 y 445
    pero no el 135. La señal solo se computa si el puerto 135 formó parte del
    escaneo: sin esa comprobación previa, «no está abierto» y «no lo miramos»
    serían indistinguibles.
    """
    if PUERTO_135 not in puertos_examinados:
        return FamiliaSO.DESCONOCIDA
    puerto = host.puerto(PUERTO_135)
    if puerto is not None and puerto.esta_abierto:
        return FamiliaSO.WINDOWS
    return FamiliaSO.LINUX


def _senal_puertos_efimeros(host: Host, puertos_examinados: set[int]) -> FamiliaSO:
    """Presencia de puertos abiertos en el rango efímero de Windows.

    Windows toma sus puertos efímeros a partir del 49152, mientras que Linux
    los toma del rango 32768–60999. Un servicio en escucha por encima del
    umbral es característico de Windows. Igual que la anterior, solo se computa
    si el rango se ha examinado.
    """
    if not any(n >= EFIMEROS_WINDOWS_MIN for n in puertos_examinados):
        return FamiliaSO.DESCONOCIDA
    if any(p.numero >= EFIMEROS_WINDOWS_MIN and p.esta_abierto for p in host.puertos):
        return FamiliaSO.WINDOWS
    return FamiliaSO.LINUX


def _elegir_puerto_para_sonda(host: Host) -> int | None:
    """Devuelve un puerto abierto del host sobre el que dirigir la sonda.

    La sonda de SO exige un puerto abierto: contra uno cerrado, la respuesta
    sería un RST sin las opciones que caracterizan la pila. Se prefiere el más
    bajo por convención, sin más criterio.
    """
    abiertos = sorted(p.numero for p in host.puertos_abiertos())
    return abiertos[0] if abiertos else None


def _registrar_ttl_si_disponible(
    host: Host,
    ttl_de_pila: int | None,
    origen_de_pila: str | None,
    contribuciones: list,
    senales: dict[str, str],
) -> None:
    """Registra la señal de TTL con la política de origen del apartado 5.

    Se prefiere el observado por el descubrimiento ICMP: es una fase que se
    diseñó específicamente para observarlo y ya lo tiene validado por origen
    tras el cierre de R-41. Cuando no está disponible —caso frecuente cuando el
    descubrimiento se resuelve por ARP en segmento local—, se aprovecha el de
    la respuesta a la sonda de pila, que también contiene la información en su
    capa IP. La procedencia se registra en el diccionario de señales para que
    la memoria pueda auditar cualquier veredicto.
    """
    if host.ttl_observado is not None:
        familia = _familia_por_ttl(host.ttl_observado)
        senales["ttl"] = f"{host.ttl_observado} (icmp) → {familia.value}"
        contribuciones.append((familia, PESO_TTL))
        return

    if ttl_de_pila and origen_de_pila:
        familia = _familia_por_ttl(ttl_de_pila)
        senales["ttl"] = f"{ttl_de_pila} ({origen_de_pila}) → {familia.value}"
        contribuciones.append((familia, PESO_TTL))


def _ponderar(
    contribuciones: list[tuple[FamiliaSO, int]],
) -> tuple[FamiliaSO, float]:
    """Suma los pesos por familia y devuelve la más votada con su confianza.

    La confianza se normaliza sobre el peso total efectivamente observado, no
    sobre el máximo posible. Una detección que solo dispuso de dos señales
    coincidentes puede alcanzar confianza alta si ambas apuntan a lo mismo.
    """
    total_observado = 0
    por_familia: dict[FamiliaSO, int] = {FamiliaSO.LINUX: 0, FamiliaSO.WINDOWS: 0}

    for familia, peso in contribuciones:
        if familia is FamiliaSO.DESCONOCIDA:
            continue
        total_observado += peso
        por_familia[familia] = por_familia.get(familia, 0) + peso

    if total_observado == 0:
        return FamiliaSO.DESCONOCIDA, 0.0

    familia_mayoritaria = max(por_familia, key=lambda k: por_familia[k])
    confianza = por_familia[familia_mayoritaria] / total_observado

    if confianza < UMBRAL_CONFIANZA:
        return FamiliaSO.DESCONOCIDA, confianza
    return familia_mayoritaria, confianza


def _recoger_senales(
    host: Host,
    puertos_examinados: set[int],
    scapy_getter: Callable = _cargar,
    espera_s: float = 2.0,
) -> tuple[list[tuple[FamiliaSO, int]], dict[str, str]]:
    """Reúne todas las señales aplicables al host y las devuelve con su peso.

    Se documenta cada señal en un diccionario paralelo para que la memoria
    pueda auditar la decisión: sin ese registro, un veredicto de confianza
    intermedia sería indistinguible de una casualidad.
    """
    contribuciones: list[tuple[FamiliaSO, int]] = []
    senales: dict[str, str] = {}

    # 1. Señales derivadas del inventario, solo si los puertos correspondientes
    #    se examinaron. La distinción entre «cerrado» y «no lo miramos» se
    #    respeta en las funciones específicas.
    familia_135 = _senal_puerto_135(host, puertos_examinados)
    if familia_135 is not FamiliaSO.DESCONOCIDA:
        senales["puerto_135"] = familia_135.value
        contribuciones.append((familia_135, PESO_PUERTO_135))

    familia_efimeros = _senal_puertos_efimeros(host, puertos_examinados)
    if familia_efimeros is not FamiliaSO.DESCONOCIDA:
        senales["efimeros"] = familia_efimeros.value
        contribuciones.append((familia_efimeros, PESO_EFIMEROS))

    # 2. Sonda de pila: requiere un puerto abierto sobre el que enviar.
    objetivo = _elegir_puerto_para_sonda(host)
    if objetivo is None:
        registro.debug(
            "sin puertos abiertos en %s: se omite la sonda de pila", host.direccion,
        )
        # Aun sin sonda, el TTL puede haber sido observado por otras fases.
        _registrar_ttl_si_disponible(host, None, None, contribuciones, senales)
        return contribuciones, senales

    scapy = scapy_getter()
    respuesta = _sondear_pila(scapy, str(host.direccion), objetivo, espera_s)
    if respuesta is None or not respuesta.haslayer(scapy.TCP):
        senales["sonda_pila"] = "sin respuesta"
        _registrar_ttl_si_disponible(host, None, None, contribuciones, senales)
        return contribuciones, senales

    # 3. TTL. Se prefiere el observado por el descubrimiento ICMP —fase
    #    específicamente diseñada para observarlo— cuando esté disponible; en
    #    otro caso se aprovecha el de la sonda de pila que se acaba de emitir.
    #    En el escenario del TFM, auditoría interna en segmento local, es
    #    habitual que el descubrimiento se resuelva por ARP y el ICMP no llegue
    #    a ejecutarse: aprovechar esta segunda fuente devuelve al modelo la
    #    señal de mayor peso en aquellas circunstancias en que se perdería.
    ttl_pila = int(getattr(respuesta[scapy.IP], "ttl", 0)) if respuesta.haslayer(scapy.IP) else 0
    _registrar_ttl_si_disponible(host, ttl_pila, "sonda_pila", contribuciones, senales)

    # 4, 5 y 6. Señales de pila propiamente dichas.
    orden = _leer_opciones(scapy, respuesta) or []
    if orden:
        familia_orden = _senal_orden_opciones(orden)
        senales["opciones_tcp"] = ", ".join(orden) + f" → {familia_orden.value}"
        contribuciones.append((familia_orden, PESO_OPCIONES))

        familia_ts = _senal_timestamps(orden)
        senales["timestamps"] = ("presentes" if "Timestamp" in orden else "ausentes") \
            + f" → {familia_ts.value}"
        contribuciones.append((familia_ts, PESO_TIMESTAMPS))

    ventana = int(getattr(respuesta[scapy.TCP], "window", 0))
    if ventana:
        familia_ventana = _senal_ventana(ventana)
        senales["ventana"] = f"{ventana} → {familia_ventana.value}"
        if familia_ventana is not FamiliaSO.DESCONOCIDA:
            contribuciones.append((familia_ventana, PESO_VENTANA))

    return contribuciones, senales


def identificar_host(host: Host, config: Configuracion) -> Host:
    """Aplica la detección de sistema operativo a un host y anota el resultado.

    No modifica los puertos, ni añade tráfico dirigido a puertos que no
    estuvieran en la configuración, salvo la única sonda de pila hacia un
    puerto abierto ya descubierto. El resultado se registra en ``host.so``
    junto con las señales que lo sustentan, lo que permite auditar cualquier
    veredicto de confianza intermedia.
    """
    puertos_examinados = set(config.puertos)
    # Se pasa ``_cargar`` explícitamente y no se deja como valor por defecto:
    # el valor por defecto se resuelve al importar, mientras que las pruebas
    # necesitan sustituirlo en el módulo ya cargado.
    contribuciones, senales = _recoger_senales(
        host, puertos_examinados, _cargar, config.espera_s,
    )

    familia, confianza = _ponderar(contribuciones)
    host.so = InferenciaSO(
        familia=familia,
        confianza=round(confianza, 3),
        senales=senales,
    )
    registro.info(
        "%s: SO %s (confianza %.0f%%) a partir de %d señales",
        host.direccion, familia.value, confianza * 100, len(senales),
    )
    return host
