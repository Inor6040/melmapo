"""Comprobación de privilegios de ejecución.

La decisión 009 establece que la herramienta exige privilegios elevados en todos
los casos y aborta si no dispone de ellos, incluso para el escaneo por conexión
completa, que técnicamente no los necesitaría. El motivo es que una degradación
silenciosa alteraría la técnica efectivamente empleada sin que el operador lo
advirtiera, lo que en un contexto de medición comprometería la comparabilidad de
los resultados: no es lo mismo un SYN Scan que un TCP Connect Scan frente a un
cortafuegos con estado, ni su rastro en los registros del objetivo es el mismo.
"""

from __future__ import annotations

import os
import sys

MENSAJE_SIN_PRIVILEGIOS = """\
Melmapo requiere privilegios elevados para ejecutarse.

Las técnicas de descubrimiento por ARP e ICMP y los escaneos SYN y ACK
construyen paquetes en crudo, operación reservada al superusuario.

Ejecute la herramienta mediante:

    sudo melmapo [opciones]

Como alternativa permanente puede concederse la capacidad correspondiente al
intérprete, si bien ello la otorga a cualquier programa que lo utilice:

    sudo setcap cap_net_raw,cap_net_admin+eip $(readlink -f $(which python3))\
"""


class SinPrivilegios(PermissionError):
    """La herramienta no dispone de los privilegios que requiere."""


def tiene_privilegios() -> bool:
    """Indica si el proceso se ejecuta con privilegios suficientes.

    En sistemas de tipo Unix la comprobación se realiza sobre el identificador
    efectivo de usuario. En otras plataformas se devuelve ``False``: la
    herramienta se desarrolla y valida exclusivamente sobre Linux conforme a la
    decisión 011, y afirmar lo contrario en un sistema no verificado sería
    ofrecer una garantía que el trabajo no ha comprobado.
    """
    if not hasattr(os, "geteuid"):
        return False
    return os.geteuid() == 0


def exigir_privilegios() -> None:
    """Verifica los privilegios y aborta la ejecución si no se dispone de ellos."""
    if not tiene_privilegios():
        raise SinPrivilegios(MENSAJE_SIN_PRIVILEGIOS)


def exigir_privilegios_o_salir(codigo: int = 1) -> None:
    """Variante para el punto de entrada: informa por la salida de error y termina."""
    try:
        exigir_privilegios()
    except SinPrivilegios as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(codigo)
