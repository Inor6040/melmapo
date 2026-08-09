# Melmapo

> Herramienta de enumeración y escaneo de red, hosts y servicios para fase de reconocimiento
> inicial en pentesting interno (red de área local), con correlación activa entre
> fingerprinting de servicio y CVEs conocidos en tiempo de escaneo.
>
> Trabajo de Fin de Máster — Máster en Seguridad Ofensiva
> (Campus Internacional de Ciberseguridad / ENIIT / UCAM), Módulo 10.

## Estado

En desarrollo activo. El razonamiento detrás de cada decisión técnica relevante se registra en
[`docs/decisions.md`](docs/decisions.md) siguiendo el esquema
*problema → alternativas → criterios → decisión → consecuencias asumidas*.

## Alcance

Ámbito de actuación: **red de área local (pentesting interno de sistemas)**, conforme al
enunciado del TFM.

### Requisitos funcionales mínimos (enunciado del máster)

| # | Capacidad | Módulo |
|---|---|---|
| 1 | Descubrimiento de máquinas: ARP Ping, TCP Ping, UDP Ping, ICMP Ping | `discovery/` |
| 2 | Enumeración de puertos abiertos: SYN Scan, TCP Connect | `scanning/` |
| 3 | Detección de filtrado por firewall: ACK Scan | `scanning/` |
| 4 | Banner grabbing para obtención de versiones de software | `fingerprint/` |
| 5 | Evaluación de cabeceras HTTP para obtención de versiones | `fingerprint/` |
| 6 | Detección de sistema operativo (diferenciación Windows / Linux) | `fingerprint/` |

Estos seis puntos constituyen el **mínimo obligatorio** y tienen prioridad de implementación
sobre cualquier otra funcionalidad.

### Aportación diferencial

Sobre ese mínimo, la herramienta añade **correlación activa fingerprint → CVE durante el
propio escaneo**, en lugar de como post-proceso separado (enfoque de `nuclei` o del script NSE
`vulners`). Esta es la contribución que sostiene la hipótesis del trabajo y se ampara en el
apartado del enunciado que valora positivamente las aportaciones adicionales en técnicas de
fingerprinting y enumeración.

## Hipótesis

Correlacionar activamente el fingerprinting de servicio con CVEs conocidos durante el escaneo
reduce el tiempo hasta un *hallazgo accionable* frente al flujo de referencia
`nmap` + NSE + búsqueda manual en NVD.

**Hallazgo accionable**, definición operacional: intervalo entre el fin de la identificación de
un servicio y la presentación del primer par (servicio, CVE) con severidad y referencia
verificable. Métrica medida en el banco de pruebas del capítulo 6 de la memoria.

## Arquitectura (esqueleto)

Núcleo modular, sin lógica implementada todavía:

```
melmapo/
├── core/           # orquestación del escaneo y modelo de datos común
├── discovery/      # ARP / TCP / UDP / ICMP Ping
├── scanning/       # SYN Scan, TCP Connect, ACK Scan
├── fingerprint/    # banner grabbing, cabeceras HTTP, detección de SO
├── correlation/    # correlación fingerprint → CVE en tiempo de escaneo
└── output/         # formato de salida (decisión pendiente, entrada 006)
```

## Requisitos

- Python 3.11+
- Privilegios elevados para las técnicas que requieren sockets raw (ARP Ping, ICMP Ping,
  SYN Scan, ACK Scan). En Windows requiere además **Npcap**. Ver `docs/decisions.md`,
  entrada 009.

## Instalación

```bash
python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e .
```

(Pendiente de dependencias reales — ver `pyproject.toml`.)

## Uso ético y legal

Herramienta desarrollada con fines académicos y de auditoría autorizada. Todas las pruebas del
TFM se ejecutan exclusivamente contra infraestructura propia en laboratorio aislado. El uso
contra sistemas de terceros sin autorización expresa puede constituir delito conforme a los
artículos 197 bis y 264 del Código Penal español.

## Licencia

GPLv3. Ver [`LICENSE`](LICENSE).
