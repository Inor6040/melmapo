# Melmapo

> Herramienta de enumeración y escaneo para la fase de reconocimiento inicial de un pentesting
> interno en red de área local.
>
> Trabajo de Fin de Máster — Máster en Seguridad Ofensiva
> (Campus Internacional de Ciberseguridad / ENIIT / UCAM), Módulo 10.

## Estado

En desarrollo activo. Las decisiones técnicas se registran en
[`docs/decisions.md`](docs/decisions.md) siguiendo el esquema
*problema → alternativas → criterios → decisión → consecuencias asumidas*.

## Alcance

Ámbito de actuación: **red de área local (pentesting interno de sistemas)**, conforme al
enunciado del TFM.

| # | Capacidad | Módulo |
|---|---|---|
| 1 | Descubrimiento de máquinas: ARP Ping, TCP Ping, UDP Ping, ICMP Ping | `discovery/` |
| 2 | Enumeración de puertos abiertos: SYN Scan, TCP Connect | `scanning/` |
| 3 | Detección de filtrado por firewall: ACK Scan | `scanning/` |
| 4 | Banner grabbing para obtención de versiones de software | `fingerprint/` |
| 5 | Evaluación de cabeceras HTTP para obtención de versiones | `fingerprint/` |
| 6 | Detección de sistema operativo (diferenciación Windows / Linux) | `fingerprint/` |

## Hipótesis

Una implementación propia de las técnicas anteriores alcanza una precisión equivalente a la de
`nmap` en la clasificación de estados de puerto (abierto / cerrado / filtrado) y en la
diferenciación entre sistemas Windows y Linux, sobre un mismo banco de pruebas en entorno
controlado, con un coste de tiempo acotado.

La validación se realiza contra el estado real conocido de los objetivos del laboratorio,
midiendo verdaderos y falsos positivos y negativos, y tomando `nmap` como herramienta de
referencia. Los resultados se recogen en el capítulo 6 de la memoria.

## Arquitectura

```
melmapo/
├── core/           # orquestación del escaneo y modelo de datos común
├── discovery/      # ARP / TCP / UDP / ICMP Ping
├── scanning/       # SYN Scan, TCP Connect, ACK Scan
├── fingerprint/    # banner grabbing, cabeceras HTTP, detección de SO
├── correlation/    # reservado (ver Líneas futuras)
└── output/         # serialización de resultados
```

## Requisitos

- Python 3.11+
- Privilegios elevados para las técnicas basadas en sockets raw (ARP Ping, ICMP Ping,
  SYN Scan, ACK Scan). En Windows requiere además **Npcap**. Ver `docs/decisions.md`,
  entrada 009.

## Instalación

```bash
python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e .
```

## Líneas futuras

Correlación automática entre el fingerprinting de servicio obtenido y CVEs conocidos, resuelta
durante el propio escaneo en lugar de como post-proceso separado. Queda fuera del alcance
comprometido de este TFM y se desarrolla únicamente si el calendario lo permite.

## Uso ético y legal

Herramienta desarrollada con fines académicos y de auditoría autorizada. Todas las pruebas se
ejecutan exclusivamente contra infraestructura propia en laboratorio aislado. El uso contra
sistemas de terceros sin autorización expresa puede constituir delito conforme a los artículos
197 bis y 264 del Código Penal español.

## Licencia

GPLv3. Ver [`LICENSE`](LICENSE).
