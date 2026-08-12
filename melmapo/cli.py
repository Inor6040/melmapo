"""Punto de entrada de Melmapo."""

from __future__ import annotations

import argparse
import logging
import sys

from . import __version__
from .core import (
    Configuracion,
    ErrorObjetivo,
    ErrorPuerto,
    Orquestador,
    Protocolo,
    TecnicaDescubrimiento,
    TecnicaEscaneo,
    parsear_objetivos,
    parsear_puertos,
)
from .core.privilegios import exigir_privilegios_o_salir

DESCRIPCION = """\
Melmapo. Enumeración y escaneo para la fase de reconocimiento inicial de un
pentesting interno en red de área local.
"""

EPILOGO = """\
Ejemplos:

  melmapo 192.168.56.0/24
  melmapo 192.168.56.20 -p 21,22,80,3306
  melmapo 192.168.56.10-40 -p 1-1024 --tecnica syn
  melmapo 192.168.56.30 -p 22,23,80 --tecnica ack -o resultado.json

Esta herramienta debe emplearse exclusivamente contra sistemas propios o sobre
los que se disponga de autorización expresa.
"""


def construir_analizador() -> argparse.ArgumentParser:
    a = argparse.ArgumentParser(
        prog="melmapo",
        description=DESCRIPCION,
        epilog=EPILOGO,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    a.add_argument("objetivos", help="dirección, red CIDR, rango o lista separada por comas")
    a.add_argument("-p", "--puertos", default=None,
                   help="puertos: suelto, rango, lista o '-' para todos (por defecto, los comunes)")
    a.add_argument("--protocolo", choices=[p.value for p in Protocolo],
                   default=Protocolo.TCP.value, help="protocolo de transporte")
    a.add_argument("--tecnica", choices=[t.value for t in TecnicaEscaneo],
                   default=TecnicaEscaneo.SYN.value, help="técnica de escaneo de puertos")
    a.add_argument("--descubrimiento", default="arp",
                   help="técnicas de descubrimiento separadas por comas: arp, icmp, tcp, udp")
    a.add_argument("-Pn", "--sin-descubrimiento", action="store_true",
                   help="omitir el descubrimiento y tratar todos los objetivos como activos")
    a.add_argument("--sin-fingerprint", action="store_true",
                   help="omitir la identificación de servicios y de sistema operativo")
    a.add_argument("-i", "--interfaz", default=None, help="interfaz de red a emplear")
    a.add_argument("-t", "--trabajadores", type=int, default=50,
                   help="número máximo de hilos simultáneos (por defecto, 50)")
    a.add_argument("-w", "--espera", type=float, default=2.0,
                   help="tiempo de espera de respuesta en segundos (por defecto, 2.0)")
    a.add_argument("-o", "--salida", default=None, help="fichero JSON de resultados")
    a.add_argument("-v", "--verboso", action="count", default=0,
                   help="aumenta el detalle del registro; puede repetirse")
    a.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return a


def _configurar_registro(nivel: int) -> None:
    niveles = {0: logging.WARNING, 1: logging.INFO}
    logging.basicConfig(
        level=niveles.get(nivel, logging.DEBUG),
        format="%(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )


def _parsear_descubrimiento(texto: str) -> list[TecnicaDescubrimiento]:
    validas = {t.value: t for t in TecnicaDescubrimiento}
    tecnicas: list[TecnicaDescubrimiento] = []
    for nombre in texto.split(","):
        nombre = nombre.strip().lower()
        if not nombre:
            continue
        if nombre not in validas:
            raise ValueError(
                f"técnica de descubrimiento desconocida: {nombre!r}. "
                f"Admitidas: {', '.join(sorted(validas))}"
            )
        tecnicas.append(validas[nombre])
    return tecnicas


def construir_configuracion(args: argparse.Namespace) -> Configuracion:
    return Configuracion(
        objetivos=parsear_objetivos(args.objetivos),
        puertos=parsear_puertos(args.puertos),
        protocolo=Protocolo(args.protocolo),
        tecnicas_descubrimiento=_parsear_descubrimiento(args.descubrimiento),
        tecnica_escaneo=TecnicaEscaneo(args.tecnica),
        trabajadores=args.trabajadores,
        espera_s=args.espera,
        interfaz=args.interfaz,
        omitir_descubrimiento=args.sin_descubrimiento,
        con_fingerprint=not args.sin_fingerprint,
    )


def main(argv: list[str] | None = None) -> int:
    args = construir_analizador().parse_args(argv)
    _configurar_registro(args.verboso)

    # La comprobación precede a cualquier otra cosa: conforme a la decisión 009
    # se exigen privilegios siempre, y es preferible advertirlo antes de que el
    # operador espere el resultado de un escaneo que no va a poder ejecutarse.
    exigir_privilegios_o_salir()

    try:
        config = construir_configuracion(args)
    except (ErrorObjetivo, ErrorPuerto, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(
        f"Objetivos: {len(config.objetivos)} | Puertos: {len(config.puertos)} | "
        f"Técnica: {config.tecnica_escaneo.value}",
        file=sys.stderr,
    )

    try:
        Orquestador(config).ejecutar()
    except KeyboardInterrupt:
        print("\ninterrumpido por el operador", file=sys.stderr)
        return 130

    # Las fases se incorporan en las jornadas siguientes; el orquestador ya las
    # admite por inyección.
    print(
        "El núcleo está operativo. Las fases de descubrimiento, escaneo y "
        "fingerprinting se incorporan en los módulos correspondientes.",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
