# Registro de decisiones técnicas

Formato de cada entrada: **Problema → Alternativas consideradas → Criterios de evaluación →
Decisión → Consecuencias y limitaciones asumidas.**

Este documento se referencia como anexo en la memoria (capítulo 5, Desarrollo de la
herramienta) y se actualiza con cada decisión relevante a lo largo del proyecto.

---

## 001 — Lenguaje de implementación

- **Problema:** elegir el lenguaje principal de la herramienta.
- **Alternativas:** Python 3.11+, Go, Rust, C#.
- **Criterios:** madurez del ecosistema específico del dominio (librerías de red y protocolos
  ofensivos), soporte de concurrencia asíncrona para operaciones intensivas en E/S de red,
  portabilidad multiplataforma, alineación con el estándar de facto del tooling ofensivo.
- **Decisión:** Python 3.11+. El enunciado del TFM recomienda explícitamente Python con Scapy
  o PowerShell, lo que refuerza la elección.
- **Consecuencias asumidas:** menor rendimiento bruto frente a implementaciones compiladas
  (Go, Rust). Mitigación prevista: `asyncio` para E/S concurrente y, si el perfilado del
  capítulo 6 lo justifica, delegación de rutas críticas en binarios optimizados. Se descarta
  C# porque su ventaja competitiva (integración nativa Windows/.NET, ejecución en memoria) es
  relevante para post-explotación en Active Directory, no para enumeración multiplataforma.

---

## 002 — Licencia

- **Problema:** elegir licencia para un repositorio público de una herramienta ofensiva.
- **Alternativas:** MIT, Apache 2.0, GPLv3, AGPLv3.
- **Criterios:** coherencia con el ecosistema de referencia (nmap es GPLv2; buena parte del
  tooling ofensivo relevante usa copyleft), garantizar que las mejoras de terceros reviertan a
  la comunidad, simplicidad frente a AGPLv3 (pensada para software como servicio, no aplica
  bien a un CLI de ejecución local).
- **Decisión:** GPLv3.
- **Consecuencias asumidas:** restringe el empaquetado en productos comerciales cerrados sin
  liberar el código derivado. No entra en conflicto con los objetivos del proyecto.

---

## 003 — Alcance de la superficie objetivo

- **Problema:** delimitar qué enumera y escanea la herramienta.
- **Alternativas:** red/hosts + servicios; web; DNS/OSINT; Active Directory; multi-superficie.
- **Criterios:** conformidad con el enunciado del TFM (que fija explícitamente "red de área
  local, pentesting interno de sistemas"), viabilidad en el plazo disponible, posibilidad de
  medir la hipótesis en banco de pruebas controlado.
- **Decisión:** red/hosts + servicios en red de área local.
- **Consecuencias asumidas:** es el terreno más ocupado por herramientas de referencia
  (nmap, masscan, rustscan), lo que obliga a una aportación diferencial explícita — ver 004.

---

## 004 — Aportación diferencial e hipótesis del TFM

- **Problema:** qué aporta esta herramienta sobre nmap/masscan/rustscan, de forma falsable y
  medible.
- **Alternativas consideradas:**
  1. Correlación activa fingerprinting de servicio ↔ CVEs conocidos en tiempo de escaneo.
  2. Motor de detección adaptativo que ajusta agresividad/paralelismo según señales de red.
  3. Salida nativa estructurada (JSON/SARIF) orientada a integración en pipelines CI/CD.
- **Criterios:** falsabilidad, medibilidad en banco de pruebas controlado (capítulo 6),
  diferenciación real frente a herramientas de referencia, encaje con el apartado del enunciado
  que valora positivamente aportaciones adicionales en fingerprinting y enumeración.
- **Decisión:** opción 1. **Hipótesis:** correlacionar activamente el fingerprinting de
  servicio con CVEs conocidos durante el propio escaneo reduce el tiempo hasta un *hallazgo
  accionable* frente al flujo de referencia nmap + NSE + búsqueda manual en NVD.
- **Definición operacional de "hallazgo accionable"** (imprescindible para que la hipótesis sea
  medible y no meramente cualitativa): intervalo entre el fin de la identificación de un
  servicio y la presentación del primer par (servicio, CVE) con severidad y referencia
  verificable.
- **Consecuencias asumidas:** la hipótesis depende de la disponibilidad de una fuente de datos
  CVE fiable y de baja latencia (ver 007). La correlación es una capa *sobre* los requisitos
  mínimos del enunciado, nunca un sustituto de ellos (ver 008).

---

## 005 — Arquitectura

- **Problema:** CLI monolítica frente a núcleo modular, con o sin sistema de plugins.
- **Criterios:** la hipótesis (004) requiere que fingerprinting y correlación operen acoplados
  en el flujo de escaneo, pero deben poder probarse por separado en el capítulo 6 (p. ej.
  sustituir la fuente CVE por un doble de prueba sin tocar el fingerprinting); el plazo
  disponible penaliza la complejidad no esencial.
- **Decisión:** núcleo modular con separación `core / discovery / scanning / fingerprint /
  correlation / output`, sin capa de plugins de terceros.
- **Consecuencias asumidas:** menor extensibilidad por terceros a corto plazo que un sistema de
  plugins. Se declara explícitamente como limitación en las conclusiones y se propone como
  línea futura (capítulo 7).

---

## 006 — [PENDIENTE] Modelo de concurrencia y formato de salida

- **Problema:** modelo de concurrencia para el escaneo y formato de serialización de resultados.
- **Alternativas de salida:** JSON propio, SARIF, HTML, combinación.
- **Dependencias:** condicionado por 007 (si la consulta CVE es remota, impacta el modelo de
  concurrencia y la latencia medida en la métrica de 004).
- **Estado:** sin decidir.

---

## 007 — [PENDIENTE] Fuente de datos CVE

- **Problema:** de dónde obtiene la herramienta los CVEs para correlacionar durante el escaneo.
- **Alternativas:** API de NVD en vivo; mirror local del feed JSON de NVD; `cve-search`/CIRCL
  autoalojado.
- **Criterios:** determinismo y reproducibilidad del banco de pruebas (depender de un servicio
  externo el día de la defensa es un riesgo operativo), latencia (impacta directamente la
  métrica de "hallazgo accionable" de 004), límites de tasa de la API pública de NVD.
- **Estado:** sin decidir. Recomendación provisional: mirror local versionado con fecha de
  snapshot documentada, para garantizar reproducibilidad. Debe cerrarse antes de implementar
  el módulo `correlation`.

---

## 008 — Prioridad de implementación: mínimo del enunciado frente a aportación diferencial

- **Problema:** el enunciado del TFM exige un conjunto cerrado de técnicas (ARP/TCP/UDP/ICMP
  Ping, SYN Scan, TCP Connect, ACK Scan, banner grabbing, cabeceras HTTP, detección de SO).
  La aportación diferencial (004) es adicional a ese conjunto y compite por el mismo tiempo
  de desarrollo.
- **Riesgo identificado:** que la correlación CVE absorba el esfuerzo y deje las técnicas
  exigidas incompletas o insuficientemente probadas, penalizando la evaluación sobre los
  criterios explícitos del enunciado para ganar en un criterio meramente valorable.
- **Decisión:** los seis requisitos funcionales mínimos se implementan y validan **antes** de
  desarrollar el módulo `correlation`. La correlación CVE se construye sobre un `fingerprint/`
  ya funcional y probado, no en paralelo.
- **Consecuencias asumidas:** si el plazo se comprime, la aportación diferencial se degrada de
  forma controlada (p. ej. correlación sobre un subconjunto reducido de servicios) sin
  comprometer el cumplimiento del enunciado. Esta degradación, de producirse, se documenta en
  las limitaciones del capítulo 7.

---

## 009 — [PENDIENTE] Privilegios de ejecución y dependencias de captura

- **Problema:** ARP Ping, ICMP Ping, SYN Scan y ACK Scan requieren construcción de paquetes en
  crudo (*raw sockets*), lo que exige privilegios elevados y, en Windows, un driver de captura.
- **Implicaciones por plataforma:** en Linux, ejecución como root o concesión de la capacidad
  `CAP_NET_RAW` al intérprete; en Windows, instalación de **Npcap** y ejecución como
  administrador. TCP Connect Scan es la única técnica de escaneo que no requiere privilegios.
- **Criterios:** portabilidad real frente a complejidad de instalación, reproducibilidad del
  banco de pruebas, degradación elegante cuando no hay privilegios disponibles.
- **Estado:** sin decidir. Opciones a evaluar: exigir privilegios siempre; detectar privilegios
  en arranque y degradar automáticamente a las técnicas disponibles (p. ej. TCP Connect en
  lugar de SYN Scan) advirtiendo al usuario. Debe documentarse en la memoria como limitación
  de despliegue en cualquier caso.

---

## 010 — [PENDIENTE] Topología del laboratorio de pruebas

- **Problema:** el enunciado circunscribe la herramienta a red de área local, y el requisito de
  descubrimiento por ARP Ping exige que los objetivos estén en el **mismo segmento de capa 2**
  que la máquina atacante. La topología del laboratorio condiciona por tanto qué requisitos
  pueden demostrarse en el capítulo 6.
- **Alternativas:** contenedores Docker con red `bridge` por defecto; Docker con red `macvlan`;
  máquinas virtuales (VirtualBox/VMware) con adaptador en modo *bridged* o red interna;
  combinación de VMs con imágenes vulnerables conocidas (Metasploitable, VulnHub).
- **Restricción técnica identificada:** la red `bridge` por defecto de Docker no reproduce
  fielmente un segmento L2 plano equivalente al de una LAN real, lo que compromete la validez
  de las pruebas de ARP Ping. `macvlan` o VMs en modo *bridged* sí lo hacen.
- **Criterios:** fidelidad respecto a una LAN real (imprescindible para ARP), reproducibilidad
  y facilidad de despliegue mediante scripts, coste en recursos de la máquina anfitriona,
  disponibilidad de objetivos heterogéneos Windows y Linux (necesarios para el requisito de
  detección de sistema operativo).
- **Estado:** sin decidir. Es la decisión con mayor impacto sobre el calendario: una elección
  errónea invalida pruebas ya ejecutadas. Debe cerrarse antes de escribir los scripts de
  despliegue del laboratorio.

---

## Consideraciones éticas y legales (transversal)

Todas las pruebas se ejecutan exclusivamente contra infraestructura propia o expresamente
autorizada, en laboratorio aislado. No se dirige tráfico contra sistemas de terceros en ningún
momento del desarrollo ni de la validación. Marco normativo aplicable: artículos 197 bis y 264
del Código Penal español y, en lo que resulte de aplicación, el Reglamento General de
Protección de Datos. Este apartado se desarrolla como sección propia en la memoria.
