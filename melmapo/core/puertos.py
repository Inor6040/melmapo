"""Interpretación de la especificación de puertos recibida por línea de órdenes.

Se admiten tres formas, combinables mediante comas:

    80              puerto suelto
    1-1024          rango
    22,80,443       lista

Además, el guion aislado designa la totalidad del espacio de puertos, y la
ausencia de especificación selecciona el conjunto por defecto.
"""

from __future__ import annotations

PUERTO_MINIMO = 1
PUERTO_MAXIMO = 65535

# Conjunto por defecto. Reúne los servicios de uso más extendido en una red
# interna y, de forma deliberada, los tres puertos del escenario de filtrado del
# laboratorio (22, 23 y 80) y los característicos de sistemas Windows (135, 139,
# 445 y 3389), que intervienen como señal en la detección de sistema operativo.
PUERTOS_POR_DEFECTO: tuple[int, ...] = (
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    993, 995, 1099, 1524, 2049, 2121, 3128, 3306, 3389, 3632,
    5432, 5900, 6000, 6667, 8009, 8080, 8180, 8443, 8787,
)


class ErrorPuerto(ValueError):
    """La especificación de puertos no es interpretable."""


def parsear_puertos(especificacion: str | None) -> list[int]:
    """Convierte una especificación textual en una lista de puertos únicos y ordenados."""
    if especificacion is None or not especificacion.strip():
        return list(PUERTOS_POR_DEFECTO)

    especificacion = especificacion.strip()
    if especificacion == "-":
        return list(range(PUERTO_MINIMO, PUERTO_MAXIMO + 1))

    puertos: set[int] = set()
    for fragmento in especificacion.split(","):
        fragmento = fragmento.strip()
        if not fragmento:
            continue
        puertos.update(_parsear_fragmento(fragmento))

    if not puertos:
        raise ErrorPuerto(f"no se ha obtenido ningún puerto de: {especificacion!r}")
    return sorted(puertos)


def _parsear_fragmento(fragmento: str) -> list[int]:
    if "-" in fragmento:
        return _parsear_rango(fragmento)
    return [_parsear_numero(fragmento)]


def _parsear_numero(texto: str) -> int:
    if not texto.isdigit():
        raise ErrorPuerto(f"puerto no numérico: {texto!r}")
    numero = int(texto)
    if not PUERTO_MINIMO <= numero <= PUERTO_MAXIMO:
        raise ErrorPuerto(
            f"puerto fuera del intervalo [{PUERTO_MINIMO}, {PUERTO_MAXIMO}]: {numero}"
        )
    return numero


def _parsear_rango(fragmento: str) -> list[int]:
    partes = fragmento.split("-")
    if len(partes) != 2:
        raise ErrorPuerto(f"rango mal formado: {fragmento!r}")

    izquierda, derecha = partes[0].strip(), partes[1].strip()
    # Formas abiertas: "-1024" equivale a 1-1024 y "1024-" a 1024-65535.
    inicio = PUERTO_MINIMO if izquierda == "" else _parsear_numero(izquierda)
    fin = PUERTO_MAXIMO if derecha == "" else _parsear_numero(derecha)

    if fin < inicio:
        raise ErrorPuerto(f"rango invertido en {fragmento!r}: {fin} es menor que {inicio}")
    return list(range(inicio, fin + 1))
