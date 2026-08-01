# Melmapo

> Herramienta de enumeración y escaneo de red, hosts y servicios.
> Trabajo de Fin de Máster — Máster en Seguridad Ofensiva (Campus Internacional de Ciberseguridad / ENIIT / UCAM).

## Estado

En desarrollo activo. Este repositorio se inicia como parte del proceso documentado en
[`docs/decisions.md`](docs/decisions.md), donde se registra el razonamiento detrás de cada
decisión técnica relevante (lenguaje, arquitectura, dependencias, formato de salida, etc.).

## Alcance (provisional)

Enumeración y escaneo de red, hosts y servicios. La aportación diferencial frente a
herramientas de referencia (nmap, masscan, rustscan) todavía no está cerrada — ver
`docs/decisions.md`, entrada 004.

## Requisitos

- Python 3.11+

## Instalación

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

(Pendiente de dependencias reales — ver `pyproject.toml`.)

## Licencia

GPLv3. Ver [`LICENSE`](LICENSE).

## Contexto académico

Este proyecto forma parte de la memoria de investigación entregada como TFM. La memoria
completa, el banco de pruebas y las consideraciones éticas y legales de los entornos de
prueba se encuentran fuera de este repositorio o en `docs/` según corresponda.
