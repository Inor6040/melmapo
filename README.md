# Melmapo

> Herramienta de enumeración y escaneo para la fase de reconocimiento inicial de un pentesting
> interno en red de área local.
>
> Trabajo de Fin de Máster — Máster en Seguridad Ofensiva
> (Campus Internacional de Ciberseguridad / ENIIT / UCAM), Módulo 10.

## Estado

**Trabajo completado.** Los seis requisitos del enunciado están implementados, probados y
comparados frente a nmap sobre el laboratorio.

- **209 pruebas** ejecutables sin acceso a red.
- **25 mediciones** en `mediciones/` que respaldan cada tabla del capítulo sexto.
- **22 decisiones formales** documentadas en `docs/decisions.md` siguiendo el esquema
  *problema → alternativas → criterios → decisión → consecuencias asumidas*.
- Comparativa empírica con nmap sobre los seis requisitos, aplicando el criterio de acierto de
  tres niveles definido en la decisión A.014 sobre resultados reales.

## Alcance

Ámbito de actuación: **red de área local (pentesting interno de sistemas)**, conforme al
enunciado del TFM.

| # | Capacidad | Módulo |
|---|---|---|
| 1 | Descubrimiento de máquinas: ARP Ping, ICMP Ping, TCP Ping (puerto 80 por defecto), UDP Ping | `discovery/` |
| 2 | Enumeración de puertos abiertos: TCP Connect y SYN Scan | `scanning/` |
| 3 | Detección de filtrado por cortafuegos: ACK Scan | `scanning/` |
| 4 | Banner grabbing para obtención de versiones de software | `fingerprint/` |
| 5 | Evaluación de cabeceras HTTP para obtención de versiones | `fingerprint/` |
| 6 | Diferenciación de sistema operativo (Linux / Windows) por señales de pila | `fingerprint/` |

## Hipótesis y su contrastación

Una implementación propia de las técnicas anteriores alcanza una precisión equivalente a la de
`nmap` en la clasificación de estados de puerto (abierto / cerrado / filtrado) y en la
diferenciación entre sistemas Windows y Linux, sobre un mismo banco de pruebas en entorno
controlado.

**Los datos sostienen la hipótesis.** En las capacidades del enunciado en las que la comparación
se ha practicado sobre los mismos puertos, la herramienta desarrollada devuelve resultados
idénticos a los de la herramienta de referencia. Las discrepancias observadas se documentan y
explican con dato propio en el capítulo 6 de la memoria.

Dos hallazgos empíricos merecen mención:

- **Nmap sustituye silenciosamente la técnica solicitada** cuando detecta ciertas combinaciones
  de opciones. La ejecución de `nmap -sn -PR --send-ip` con `--packet-trace` revela que la
  herramienta emite en paralelo cuatro sondas distintas (ICMP Echo, SYN al 443, ACK al 80,
  Timestamp Request), ignorando la solicitud de ARP sin emitir aviso al operador. La evidencia
  está en `mediciones/20260823_nmap_diag_pr.txt`.
- **Nmap falla la versión del kernel de Ubuntu Server**: `nmap -O` sitúa el sistema en el rango
  `Linux 4.15 - 5.19` cuando el kernel real es 6.x. La herramienta desarrollada, con criterio
  conservador, emite solo la familia (Linux) con confianza 100 %, resultado más ajustado a la
  realidad que el veredicto más informativo pero incorrecto de la referencia.

La validación se realiza contra el estado real conocido de los objetivos del laboratorio,
midiendo verdaderos y falsos positivos y negativos, con nmap como herramienta de referencia
comparada. Las tablas de resultados están en los subapartados 6.5.1 a 6.5.6 y agregadas en el
6.6 de la memoria.

## Arquitectura

```
melmapo/
├── core/           # orquestación del escaneo y modelo de datos común
├── discovery/      # ARP / ICMP / TCP / UDP Ping
├── scanning/       # TCP Connect, SYN Scan, ACK Scan
├── fingerprint/    # banner grabbing, cabeceras HTTP, detección de SO
├── correlation/    # reservado (ver Líneas futuras)
└── output/         # serialización JSON y salida por consola
```

## Requisitos

- **Python 3.11 o superior.**
- **Scapy 2.7.0 o superior** (única dependencia de tiempo de ejecución).
- **Privilegios elevados** para las técnicas basadas en paquetes en crudo: ARP Ping, ICMP Ping,
  TCP Ping, UDP Ping, SYN Scan, ACK Scan y detección de sistema operativo. En Windows requiere
  además **Npcap**. Ver `docs/decisions.md`, entrada 009.

## Instalación

```bash
git clone https://github.com/Inor6040/melmapo.git
cd melmapo
python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e .
```

## Uso básico

Ejecución por defecto contra tres objetivos con siete puertos habituales:

```bash
sudo melmapo 192.168.56.20,192.168.56.30,192.168.56.40 -p 22,80,135,139,443,445,49664
```

Salida (fragmento):

```
Objetivos: 3 | Puertos: 7 | Técnica: syn

Host 192.168.56.20  (00:0c:29:20:b5:39)
  Responde a: arp
  Sistema operativo: linux (confianza 57%)
  PUERTO    ESTADO             SERVICIO         VERSIÓN
  22/tcp    abierto            OpenSSH          4.7p1
  80/tcp    abierto            Apache           2.2.8
  139/tcp   abierto            —                —
  445/tcp   abierto            —                —
  (3 puertos cerrados no mostrados)

Host 192.168.56.30  (00:0c:29:01:3f:68)
  Responde a: arp
  Sistema operativo: linux (confianza 100%)
  PUERTO    ESTADO             SERVICIO         VERSIÓN
  22/tcp    abierto            OpenSSH          10.2p1
  80/tcp    filtrado           —                —
  (5 puertos cerrados no mostrados)

Host 192.168.56.40  (00:0c:29:5f:57:57)
  Responde a: arp
  Sistema operativo: windows (confianza 100%)
  ...

3 host(s) activo(s) de 3 examinado(s) en 6.54 s
```

Otros ejemplos de invocación figuran en el epílogo de la ayuda (`melmapo --help`) y en el
apartado B.1 de la memoria, que recoge las invocaciones exactas empleadas en las mediciones del
capítulo sexto.

## Reproducibilidad

Cualquier medición citada en el capítulo sexto de la memoria puede reproducirse a partir del
fichero JSON correspondiente en el directorio `mediciones/`. El nombre de cada fichero
identifica la fecha, la herramienta empleada, la técnica y el escenario según la convención
`YYYYMMDD_herramienta_tecnica_escenario.ext`. Los parámetros exactos con los que se ejecutó cada
medición figuran en el propio fichero bajo el campo `parametros`.

Las pruebas se lanzan con `pytest` desde la raíz del proyecto y se ejecutan en pocos segundos
por no depender de acceso a red: los módulos que operan sobre paquetes en crudo se sustituyen
por dobles que devuelven respuestas preparadas.

```bash
pip install -e ".[dev]"
pytest
```

## Documentación

- **`docs/decisions.md`** — Registro completo de las 22 decisiones formales tomadas durante el
  desarrollo, con problema, alternativas consideradas, criterios aplicados, decisión adoptada y
  consecuencias asumidas.
- **`docs/laboratorio.md`** — Configuración detallada del laboratorio empleado en la validación.
- **`mediciones/`** — 25 ficheros JSON, XML y trazas de `--packet-trace` que sostienen las
  tablas del capítulo sexto.

## Líneas futuras

- Correlación con bases de datos de vulnerabilidades públicas (NVD o equivalente) resuelta
  durante el propio escaneo. El paquete `correlation/` está previsto por la decisión 007 con
  este propósito.
- Sistema de extensiones que permita añadir técnicas nuevas sin modificar el árbol del proyecto.
- Degradación selectiva de técnicas según los privilegios disponibles, en lugar del rechazo
  actual cuando el operador no dispone de ellos.
- Formatos de salida adicionales (SARIF, XML compatible con nmap) para integración con flujos
  existentes.
- Ampliación del modelo de detección de sistema operativo a más familias (BSD, macOS,
  dispositivos de red).
- Modelo adaptativo de temporizadores en lugar del temporizador fijo actual.
- Cobertura de HTTPS con envoltura TLS del socket.
- Sondas específicas para protocolos binarios (telnet, SMB, NetBIOS) que actualmente quedan sin
  identificar por el módulo de banner grabbing.

## Uso ético y legal

Herramienta desarrollada con fines académicos y de auditoría autorizada. Todas las pruebas se
ejecutan exclusivamente contra infraestructura propia en laboratorio aislado. El uso contra
sistemas de terceros sin autorización expresa puede constituir delito conforme a los artículos
197 bis y 264 del Código Penal español.

## Licencia

GPL-3.0-only. Ver [`LICENSE`](LICENSE).