"""Utilidades de red compartidas por los módulos de identificación de servicios.

Los dos módulos —banner grabbing y cabeceras HTTP— comparten el patrón básico:
conectar a un puerto abierto con un temporizador conservador, hablar con el
servicio en la medida que la técnica requiere, y devolver una cadena decodificada
sobre la que operar. La lógica común se centraliza aquí para que ambos módulos se
diferencien únicamente en lo que aportan sobre esa base.
"""

from __future__ import annotations

import socket
from typing import Callable

# Los banners y las cabeceras HTTP son ASCII o UTF-8 en la práctica totalidad de
# los casos, pero los primeros pueden contener bytes de protocolo binario
# —MySQL es el caso más claro— o secuencias no válidas por configuración
# incorrecta del servicio. La decodificación como ``latin-1`` no falla nunca y
# preserva la cadena original byte a byte, que es lo que exige la decisión 014
# sobre auditabilidad.
CODIFICACION = "latin-1"

# Tamaño máximo de lectura. Los banners útiles son cortos y ampliar este límite
# no aporta información sobre el servicio; conviene, en cambio, para no dejar la
# conexión abierta esperando datos que un servidor mal configurado podría enviar
# indefinidamente.
LECTURA_MAX = 4096


def _conectar(direccion: str, puerto: int, espera_s: float) -> socket.socket:
    """Establece una conexión TCP en claro con el objetivo."""
    conexion = socket.create_connection((direccion, puerto), timeout=espera_s)
    conexion.settimeout(espera_s)
    return conexion


def dialogar(
    direccion: str,
    puerto: int,
    espera_s: float,
    estimulo: bytes | None = None,
) -> str | None:
    """Establece la conexión, opcionalmente envía un estímulo y lee la respuesta.

    Devuelve la cadena decodificada, o ``None`` si la conexión no llega a
    establecerse o si el servicio la cierra sin decir nada. Los errores de red se
    resuelven silenciosamente en la capa que orquesta la técnica: aquí solo se
    traduce «no obtuve nada» a ``None``.
    """
    try:
        conexion = _conectar(direccion, puerto, espera_s)
    except OSError:
        return None

    try:
        if estimulo is not None:
            try:
                conexion.sendall(estimulo)
            except OSError:
                return None

        datos = bytearray()
        while len(datos) < LECTURA_MAX:
            try:
                trozo = conexion.recv(LECTURA_MAX - len(datos))
            except socket.timeout:
                break
            except OSError:
                break
            if not trozo:
                break
            datos.extend(trozo)
    finally:
        try:
            conexion.close()
        except OSError:
            pass

    if not datos:
        return None
    return bytes(datos).decode(CODIFICACION, errors="replace")


def con_dialogo(
    funcion_dialogo: Callable[[str, int, float], str | None] = dialogar,
) -> Callable[[str, int, float], str | None]:
    """Punto de sustitución para las pruebas.

    Los módulos que se apoyan en ``dialogar`` pueden inyectar aquí un doble sin
    tocar código de red real. La forma de la firma es intencionalmente estrecha:
    solo lo que un servicio real necesita.
    """
    return funcion_dialogo
