"""Interpretación de la especificación de objetivos recibida por línea de órdenes.

Se admiten cuatro formas, combinables mediante comas:

    192.168.56.10                    dirección suelta
    192.168.56.0/24                  notación CIDR
    192.168.56.10-20                 rango sobre el último octeto
    192.168.56.10-192.168.56.40      rango entre dos direcciones completas

El alcance del trabajo se circunscribe a redes de área local (decisión 003), de
modo que solo se contempla IPv4.
"""

from __future__ import annotations

from ipaddress import AddressValueError, IPv4Address, IPv4Network

# Límite de seguridad. Una máscara de 16 bits ya supone 65 534 direcciones, muy
# por encima de lo que cabe esperar en el segmento de un pentesting interno; un
# prefijo menor es casi siempre un error de escritura y conviene detenerlo antes
# de generar millones de objetivos.
PREFIJO_MINIMO = 16


class ErrorObjetivo(ValueError):
    """La especificación de objetivos no es interpretable."""


def parsear_objetivos(especificacion: str) -> list[IPv4Address]:
    """Convierte una especificación textual en una lista de direcciones únicas y ordenadas."""
    if not especificacion or not especificacion.strip():
        raise ErrorObjetivo("la especificación de objetivos está vacía")

    direcciones: set[IPv4Address] = set()
    for fragmento in especificacion.split(","):
        fragmento = fragmento.strip()
        if not fragmento:
            continue
        direcciones.update(_parsear_fragmento(fragmento))

    if not direcciones:
        raise ErrorObjetivo(f"no se ha obtenido ningún objetivo de: {especificacion!r}")
    return sorted(direcciones)


def _parsear_fragmento(fragmento: str) -> list[IPv4Address]:
    if "/" in fragmento:
        return _parsear_cidr(fragmento)
    if "-" in fragmento:
        return _parsear_rango(fragmento)
    return [_parsear_direccion(fragmento)]


def _parsear_direccion(texto: str) -> IPv4Address:
    try:
        return IPv4Address(texto)
    except AddressValueError as exc:
        raise ErrorObjetivo(f"dirección no válida: {texto!r}") from exc


def _parsear_cidr(fragmento: str) -> list[IPv4Address]:
    try:
        red = IPv4Network(fragmento, strict=False)
    except (AddressValueError, ValueError) as exc:
        raise ErrorObjetivo(f"red no válida: {fragmento!r}") from exc

    if red.prefixlen < PREFIJO_MINIMO:
        raise ErrorObjetivo(
            f"prefijo demasiado amplio en {fragmento!r}: /{red.prefixlen}. "
            f"El mínimo admitido es /{PREFIJO_MINIMO}"
        )

    # Para /31 y /32 no existe la distinción entre dirección de red y de
    # difusión, y hosts() devuelve la dirección o el par correspondiente.
    return list(red.hosts()) or [red.network_address]


def _parsear_rango(fragmento: str) -> list[IPv4Address]:
    partes = fragmento.split("-")
    if len(partes) != 2:
        raise ErrorObjetivo(f"rango mal formado: {fragmento!r}")

    izquierda, derecha = partes[0].strip(), partes[1].strip()
    inicio = _parsear_direccion(izquierda)

    if "." in derecha:
        fin = _parsear_direccion(derecha)
    else:
        # Forma abreviada: solo se indica el último octeto del extremo superior.
        if not derecha.isdigit():
            raise ErrorObjetivo(f"extremo superior no válido en {fragmento!r}: {derecha!r}")
        ultimo = int(derecha)
        if not 0 <= ultimo <= 255:
            raise ErrorObjetivo(f"octeto fuera de rango en {fragmento!r}: {ultimo}")
        base = ".".join(izquierda.split(".")[:3])
        fin = _parsear_direccion(f"{base}.{ultimo}")

    if int(fin) < int(inicio):
        raise ErrorObjetivo(
            f"rango invertido en {fragmento!r}: {fin} es anterior a {inicio}"
        )

    cantidad = int(fin) - int(inicio) + 1
    if cantidad > 65536:
        raise ErrorObjetivo(f"rango demasiado amplio en {fragmento!r}: {cantidad} direcciones")

    return [IPv4Address(v) for v in range(int(inicio), int(fin) + 1)]
