"""Presentación de resultados.

Conforme a la decisión 006 se ofrecen dos salidas con destinatarios distintos:
una tabla legible por consola, destinada al operador que sigue la ejecución, y
un fichero JSON que refleja el modelo de datos completo y permite el
procesamiento posterior. El banco de pruebas del capítulo de casos de prueba se
apoya en el segundo, que conserva los banners en bruto y las latencias
necesarias para reproducir el cómputo de aciertos.
"""

from __future__ import annotations

import json
from pathlib import Path

from ..core.modelo import EstadoPuerto, Host, ResultadoEscaneo

# Solo se listan los estados que aportan información. Un barrido de mil puertos
# produce casi mil cerrados, cuya enumeración ocultaría lo relevante; se
# resumen en una línea al pie de cada host.
ESTADOS_VISIBLES = (
    EstadoPuerto.ABIERTO,
    EstadoPuerto.FILTRADO,
    EstadoPuerto.NO_FILTRADO,
    EstadoPuerto.ABIERTO_FILTRADO,
)


def a_json(resultado: ResultadoEscaneo, indentado: int = 2) -> str:
    return json.dumps(resultado.a_diccionario(), indent=indentado, ensure_ascii=False)


def guardar_json(resultado: ResultadoEscaneo, ruta: str | Path) -> Path:
    destino = Path(ruta)
    destino.parent.mkdir(parents=True, exist_ok=True)
    destino.write_text(a_json(resultado), encoding="utf-8")
    return destino


def _fila(numero: str, estado: str, servicio: str, version: str) -> str:
    return f"  {numero:<9} {estado:<18} {servicio:<16} {version}"


def _bloque_host(host: Host) -> list[str]:
    lineas: list[str] = []
    cabecera = f"Host {host.direccion}"
    if host.mac:
        cabecera += f"  ({host.mac}"
        cabecera += f", {host.fabricante})" if host.fabricante else ")"
    lineas.append(cabecera)

    if host.tecnicas_respondidas:
        detalle = ", ".join(t.value for t in host.tecnicas_respondidas)
        if host.ttl_observado is not None:
            detalle += f" | tiempo de vida {host.ttl_observado}"
        lineas.append(f"  Responde a: {detalle}")

    if host.so is not None and host.so.confianza > 0:
        lineas.append(
            f"  Sistema operativo: {host.so.familia.value} "
            f"(confianza {host.so.confianza:.0%})"
        )

    if not host.puertos:
        lineas.append("  Sin puertos examinados")
        return lineas

    visibles = [p for p in host.puertos if p.estado in ESTADOS_VISIBLES]
    cerrados = len(host.puertos) - len(visibles)

    if visibles:
        lineas.append(_fila("PUERTO", "ESTADO", "SERVICIO", "VERSIÓN"))
        for p in visibles:
            servicio = p.servicio.nombre if p.servicio and p.servicio.nombre else "—"
            version = p.servicio.version if p.servicio and p.servicio.version else "—"
            lineas.append(
                _fila(f"{p.numero}/{p.protocolo.value}", p.estado.value, servicio, version)
            )
    else:
        lineas.append("  Ningún puerto abierto ni filtrado")

    if cerrados:
        lineas.append(f"  ({cerrados} puertos cerrados no mostrados)")
    return lineas


def tabla_consola(resultado: ResultadoEscaneo) -> str:
    activos = resultado.hosts_activos()
    lineas: list[str] = []

    if not activos:
        lineas.append("No se ha encontrado ningún host activo.")
    else:
        for host in activos:
            lineas.extend(_bloque_host(host))
            lineas.append("")

    resumen = f"{len(activos)} host(s) activo(s) de {len(resultado.hosts)} examinado(s)"
    if resultado.duracion_s is not None:
        resumen += f" en {resultado.duracion_s:.2f} s"
    lineas.append(resumen)
    return "\n".join(lineas)
