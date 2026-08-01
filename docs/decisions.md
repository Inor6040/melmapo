# Registro de decisiones técnicas

Formato de cada entrada: **Problema → Alternativas consideradas → Criterios de evaluación →
Decisión → Consecuencias y limitaciones asumidas.**

Este documento se referencia como anexo en la memoria (capítulo de Desarrollo de la
herramienta) y se actualiza con cada decisión relevante a lo largo del proyecto.

---

## 001 — Lenguaje de implementación

- **Problema:** elegir el lenguaje principal de la herramienta.
- **Alternativas:** Python 3.11+, Go, Rust, C#.
- **Criterios:** madurez del ecosistema específico del dominio (librerías de red y protocolos
  ofensivos), soporte de concurrencia asíncrona para operaciones intensivas en E/S de red,
  portabilidad multiplataforma, alineación con el estándar de facto del tooling ofensivo
  (adopción y extensibilidad por terceros).
- **Decisión:** Python 3.11+.
- **Consecuencias asumidas:** menor rendimiento bruto frente a implementaciones compiladas
  (Go, Rust). Mitigación prevista: uso de `asyncio`/`aiohttp` para E/S concurrente y, si el
  perfilado en el capítulo 6 lo justifica, delegación de rutas críticas en binarios optimizados
  externos. Se descarta C# porque su ventaja competitiva (integración nativa Windows/.NET,
  ejecución en memoria) es relevante para tooling de post-explotación en Active Directory, no
  para una herramienta de enumeración y escaneo multiplataforma.

---

## 002 — Licencia

- **Problema:** elegir licencia para un repositorio público de una herramienta ofensiva de
  enumeración/escaneo.
- **Alternativas:** MIT, Apache 2.0, GPLv3, AGPLv3.
- **Criterios:** coherencia con el ecosistema de referencia (nmap es GPLv2; buena parte del
  tooling ofensivo relevante usa licencias copyleft), garantizar que mejoras de terceros
  reviertan a la comunidad, simplicidad frente a AGPLv3 (pensada para software como servicio,
  no aplica bien a un CLI/librería de ejecución local).
- **Decisión:** GPLv3.
- **Consecuencias asumidas:** restringe el empaquetado de la herramienta en productos
  comerciales cerrados sin liberar el código derivado. No entra en conflicto con los objetivos
  del proyecto.

---

## 003 — Alcance de la superficie objetivo

- **Problema:** delimitar qué enumera y escanea la herramienta.
- **Alternativas:** red/hosts + servicios; web; DNS/OSINT; Active Directory; combinación
  multi-superficie.
- **Criterios:** viabilidad en los días de desarrollo, existencia de una aportación diferencial
  defendible frente a herramientas de referencia, posibilidad de medir la hipótesis en un
  banco de pruebas controlado (capítulo 6).
- **Decisión:** red/hosts + servicios.
- **Consecuencias asumidas:** es el terreno más ocupado por herramientas de referencia
  (nmap, masscan, rustscan). **Pendiente crítico:** la aportación diferencial frente a estas
  herramientas no está cerrada todavía — sin ella, no podre defender bien la tesis (ver criterios del proyecto). Debo resolverlo antes de iniciar el desarrollo del motor de escaneo.

---

## 004 — [PENDIENTE] Aportación diferencial

- **Problema:** qué hace esta herramienta que nmap/masscan/rustscan no hagan, de forma
  medible.
- **Alternativas en discusión:**
  1. Correlación activa fingerprinting de servicio ↔ CVEs conocidos en tiempo de escaneo
     (no como post-proceso separado).
  2. Motor de detección adaptativo que ajusta agresividad/paralelismo según señales de red
     (latencia, pérdida de paquetes) en lugar de flags estáticos.
  3. Salida nativa estructurada (JSON/SARIF normalizado desde el diseño) orientada a
     integración en pipelines CI/CD ofensivos.
- **Estado:** sin decidir.
