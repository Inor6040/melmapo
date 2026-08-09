# Registro de decisiones técnicas

Este documento recoge las decisiones de diseño e implementación tomadas durante el desarrollo de
Melmapo. Cada entrada describe el problema de partida, las alternativas que se valoraron, los
criterios aplicados, la decisión adoptada y las consecuencias que se aceptan al tomarla. Se
incluye como anexo de la memoria, en el capítulo dedicado al desarrollo de la herramienta.

---

## 001 — Lenguaje de implementación

La primera decisión del proyecto era el lenguaje. Se valoraron Python, Go, Rust y C#.

Go y Rust ofrecen un rendimiento muy superior en operaciones de red intensivas, pero su ecosistema
de librerías orientadas a la manipulación de paquetes en crudo es considerablemente más pobre que
el de Python, y la curva de desarrollo es más lenta. C# resultaba atractivo por su integración
nativa con Windows, aunque esa ventaja se manifiesta sobre todo en herramientas de post-explotación
en entornos Active Directory: para una herramienta de enumeración que debe operar contra objetivos
heterogéneos, aporta poco.

Python reúne, en cambio, un conjunto de librerías maduro y específico del dominio —Scapy en primer
lugar—, permite iterar con rapidez sobre el diseño y constituye el estándar de facto en el
instrumental ofensivo, lo que facilita que terceros lean, comprendan y extiendan el código. El
propio enunciado del trabajo lo recomienda de forma explícita.

**Se opta por Python 3.11 o superior.** Se acepta como contrapartida un rendimiento bruto inferior
al de una implementación compilada, penalización que resulta poco relevante en el escenario
objetivo, una red de área local con un número acotado de equipos. Conviene señalar que la
justificación inicial apelaba también a las capacidades de concurrencia asíncrona del lenguaje;
ese argumento quedó matizado más adelante por la decisión 006b, al comprobarse que la dependencia
de Scapy impone un modelo basado en hilos.

---

## 002 — Licencia

Para un repositorio público que aloja una herramienta de seguridad ofensiva se consideraron MIT,
Apache 2.0, GPLv3 y AGPLv3.

Las licencias permisivas facilitan la adopción, pero no garantizan que las mejoras introducidas por
terceros reviertan a la comunidad. AGPLv3 fue descartada por inadecuación: su cláusula de uso en
red está pensada para software ofrecido como servicio, no para una herramienta de línea de comandos
que se ejecuta localmente. Pesó además la coherencia con el ecosistema: nmap se distribuye bajo
GPLv2 y buena parte del instrumental de referencia emplea licencias copyleft.

**Se adopta GPLv3.** La consecuencia es que la herramienta no podrá integrarse en productos
comerciales cerrados sin liberar el código derivado, lo que no supone conflicto alguno con los
fines del proyecto.

---

## 003 — Alcance de la superficie objetivo

Una herramienta de reconocimiento puede orientarse a superficies muy distintas: la red y sus
equipos, la capa web, la información expuesta mediante DNS y fuentes abiertas, o los servicios de
directorio. También cabía una aproximación multi-superficie.

El enunciado del trabajo resuelve buena parte de la cuestión al circunscribir el ámbito de
actuación a la red de área local, en un contexto de pentesting interno de sistemas. A ello se suma
un criterio de orden metodológico: la superficie elegida debe permitir contrastar la hipótesis
contra un estado real conocido, lo que resulta mucho más viable con equipos y servicios de red que
con superficies donde el resultado esperado es difícil de establecer de antemano.

**El alcance se fija en el descubrimiento de equipos y la enumeración de sus servicios dentro de
una red de área local.** Se asume que se trata del terreno más transitado por herramientas
consolidadas, circunstancia que obliga a que la validación descanse sobre evidencia medida y no
sobre apreciaciones cualitativas.

---

## 004 — Hipótesis del trabajo

Formular la hipótesis exigía encontrar un enunciado que fuera a la vez falsable y demostrable con
los medios del laboratorio. Se barajaron tres.

La primera planteaba comparar la precisión de la herramienta con la de una implementación de
referencia. La segunda proponía correlacionar el fingerprinting obtenido con bases de datos de
vulnerabilidades durante el propio escaneo, midiendo la reducción del tiempo hasta obtener un
hallazgo accionable. La tercera apuntaba a un motor capaz de ajustar su agresividad según las
condiciones observadas de la red.

La segunda y la tercera resultaban más originales, pero ambas trasladaban el peso de la
demostración fuera de lo que el enunciado exige: la segunda dependía de una fuente externa de datos
cuya disponibilidad y latencia condicionaban la medición, y la tercera requería inducir condiciones
de red degradadas de forma reproducible, algo difícil de garantizar en un entorno virtualizado. La
primera, en cambio, se apoya íntegramente en las técnicas que el trabajo debe implementar de todos
modos, y admite una contrastación numérica limpia.

**La hipótesis queda formulada así:** una implementación propia de las técnicas de descubrimiento,
escaneo y fingerprinting recogidas en el enunciado alcanza una precisión equivalente a la de nmap
en la clasificación de estados de puerto —abierto, cerrado y filtrado— y en la diferenciación entre
sistemas Windows y Linux, sobre un mismo banco de pruebas en entorno controlado y con un coste
temporal acotado.

Su contrastación se realiza midiendo verdaderos y falsos positivos y negativos contra la tabla de
estado real del laboratorio descrita en la decisión 010, empleando nmap como referencia y repitiendo
cada medición un mínimo de cinco veces para poder reportar media y desviación típica. Se asume que
la hipótesis es conservadora: no aspira a superar a la herramienta de referencia, sino a demostrar
equivalencia funcional en un subconjunto acotado de técnicas.

---

## 005 — Arquitectura

La alternativa era entre una herramienta monolítica de línea de comandos y un núcleo dividido en
módulos, con la opción adicional de incorporar un sistema de extensiones de terceros.

Dos consideraciones inclinaron la balanza. La primera, de orden experimental: el banco de pruebas
debe poder ejercitar cada técnica de forma aislada, lo que exige que estén separadas y sean
invocables de manera independiente. La segunda, de orden expositivo: una correspondencia directa
entre los requisitos del enunciado y las unidades de código hace verificable esa correspondencia,
tanto en la memoria como durante la defensa.

**Se adopta un núcleo modular** organizado en `core`, `discovery`, `scanning`, `fingerprint`,
`correlation` y `output`. Se prescinde del sistema de extensiones: aportaría flexibilidad para
terceros, pero introduce una capa de indirección que no beneficia a los objetivos del trabajo y
dificulta seguir el flujo de ejecución al leer el código. Queda recogido entre las líneas futuras.
El paquete `correlation` se mantiene reservado en la estructura, sin implementación, conforme a lo
expuesto en la decisión 007.

---

## 006 — Formato de salida

Los resultados de un escaneo tienen dos consumidores distintos: el operador que está frente a la
consola mientras la herramienta trabaja, y cualquier proceso posterior que necesite explotar esos
datos. Servir a ambos con un único formato obliga a comprometer uno de los dos.

Se valoraron JSON, SARIF, HTML, CSV y la salida exclusiva por consola. SARIF se descartó por
inadecuación conceptual: está diseñado para hallazgos de análisis estático de código y su
aplicación a resultados de escaneo de red exigiría forzar el mapeo de los campos. HTML y CSV no
aportan nada que JSON no cubra ya, y su generación desviaría esfuerzo de la validación
experimental.

**Se implementa una salida doble:** serialización a JSON en fichero, con una estructura que refleja
fielmente el modelo de datos del núcleo, y presentación en tabla legible por consola durante la
ejecución. Los formatos descartados quedan como línea futura.

---

## 006b — Modelo de concurrencia

El escaneo de red es una carga dominada por la espera: la mayor parte del tiempo transcurre
aguardando respuestas que pueden no llegar. Paralelizar es, por tanto, imprescindible.

La opción inicialmente prevista era `asyncio`, pero choca con una limitación de Scapy: sus
primitivas de envío y recepción son síncronas y bloqueantes, y no se integran con el bucle de
eventos sin recurrir a envoltorios que anulan buena parte de la ventaja. Cabía un modelo híbrido,
con hilos para las técnicas basadas en Scapy y corrutinas para las basadas en sockets estándar,
pero mantener dos paradigmas de concurrencia simultáneos supone duplicar la gestión de errores y de
cancelaciones, y multiplicar las formas en que el programa puede fallar de manera difícil de
diagnosticar.

**Se opta por `ThreadPoolExecutor` de forma uniforme**, con un límite de trabajadores configurable.
Conviene añadir que el principal factor de rendimiento en la fase de descubrimiento no reside en la
concurrencia del intérprete sino en las primitivas de envío por lotes de Scapy, capaces de resolver
una barrida completa de subred en una sola invocación. Se acepta un rendimiento inferior al de una
implementación asíncrona pura en escenarios de concurrencia muy elevada, situación que queda fuera
del alcance definido en la decisión 003. Esta decisión revisa el supuesto de asincronía enunciado
en la 001.

---

## 007 — Correlación con vulnerabilidades conocidas

Se estudió la posibilidad de que la herramienta relacionase automáticamente las versiones de
software identificadas mediante fingerprinting con vulnerabilidades públicamente documentadas,
resolviendo esa correlación durante el propio escaneo.

Las vías examinadas fueron la consulta en vivo a la API de NVD, la réplica local de sus ficheros de
distribución y el despliegue propio de una instancia de `cve-search`. Ninguna resultó satisfactoria
para los fines de este trabajo. La consulta en vivo introduce una dependencia externa sujeta a
límites de tasa que compromete la reproducibilidad del banco de pruebas. La réplica local resuelve
ese problema, pero deja intacto el verdaderamente difícil: la correspondencia entre las cadenas de
versión que devuelve un banner, con sus formatos heterogéneos y frecuentemente incompletos, y los
identificadores CPE normalizados que emplean las bases de datos de vulnerabilidades. Esa
normalización constituye por sí sola un problema de investigación, y abordarla a medias produciría
correlaciones poco fiables que restarían solidez al conjunto.

**La funcionalidad queda fuera del alcance comprometido.** Se documenta como línea futura en las
conclusiones y el paquete `correlation` permanece reservado en la estructura del proyecto. Se
asume que el trabajo renuncia con ello a una aportación de mayor originalidad, a cambio de que la
validación experimental descanse sobre resultados que pueden verificarse íntegramente contra el
laboratorio.

---

## 008 — Prioridad de implementación

El enunciado establece seis capacidades que la herramienta debe reunir: descubrimiento de equipos
mediante ARP, TCP, UDP e ICMP Ping; enumeración de puertos abiertos mediante SYN Scan y TCP
Connect; detección de filtrado mediante ACK Scan; obtención de versiones por banner grabbing;
obtención de versiones por evaluación de cabeceras HTTP; y diferenciación entre sistemas Windows y
Linux.

Existe una razón técnica, y no solo de organización del trabajo, para tratarlas como base sobre la
que construir cualquier otra cosa: toda funcionalidad adicional que quepa imaginar en una
herramienta de este tipo se apoya en la salida del fingerprinting. Edificar sobre un módulo aún no
validado significaría arrastrar sus errores hacia arriba y no poder discernir después si un
resultado incorrecto procede de la capa nueva o del cimiento.

**Los seis requisitos se implementan y se validan contra el laboratorio antes de abordar cualquier
funcionalidad adicional.** Se acepta que el resultado será una herramienta de alcance deliberadamente
acotado, y se prioriza la completitud verificable sobre la ambición funcional.

---

## 009 — Privilegios de ejecución

Cuatro de las técnicas previstas —ARP Ping, ICMP Ping, SYN Scan y ACK Scan— construyen paquetes en
crudo y requieren por ello privilegios elevados. TCP Connect Scan es la única que puede operar sin
ellos, al apoyarse en la pila del sistema operativo.

Cabían dos comportamientos. El primero, detectar los privilegios disponibles al arrancar y degradar
automáticamente a las técnicas ejecutables, advirtiendo al usuario. El segundo, exigirlos siempre y
abortar si no se dispone de ellos. La degradación automática resulta más cómoda, pero introduce un
riesgo que en un contexto de medición no es menor: el usuario podría creer que está ejecutando un
SYN Scan cuando en realidad se le ha sustituido por un TCP Connect, con un perfil de detección y un
comportamiento frente a cortafuegos distintos. Trasladado al banco de pruebas, eso comprometería la
comparabilidad de los resultados.

**La herramienta exige privilegios elevados en todos los casos**, los comprueba al arrancar y, de no
tenerlos, aborta con un mensaje explicativo. Se acepta que la exigencia es más restrictiva de lo
estrictamente necesario, dado que una de las técnicas podría prescindir de ella, a cambio de un
comportamiento uniforme y de la certeza de que la técnica ejecutada es siempre la solicitada. La
degradación selectiva queda recogida como línea futura.

---

## 010 — Topología del laboratorio de pruebas

El entorno de pruebas debe permitir demostrar las seis capacidades exigidas, y dos de ellas imponen
condiciones estructurales. El descubrimiento mediante ARP solo funciona si los objetivos residen en
el mismo dominio de difusión que la máquina atacante, por operar en capa de enlace. La detección de
filtrado, a su vez, carece de sentido si no existe un objetivo con reglas de cortafuegos conocidas
y controladas por quien realiza la prueba.

Se consideraron contenedores Docker, tanto con red puente como con `macvlan`, y máquinas virtuales,
tanto en modo puente sobre la red doméstica como sobre un segmento virtual aislado. La red puente
por defecto de Docker quedó descartada porque no reproduce un dominio de difusión equivalente al de
una red física, lo que invalidaría las pruebas de ARP. El modo puente sobre la red doméstica se
descartó por razones éticas y legales: implicaría dirigir tráfico de escaneo hacia equipos ajenos
al laboratorio.

**El laboratorio se compone de cuatro máquinas virtuales sobre VMware Workstation, conectadas a un
segmento virtual dedicado en modo *host-only*, con el servidor DHCP desactivado y direccionamiento
estático.** La máquina atacante dispone de un segundo adaptador en modo NAT, empleado únicamente
para la instalación de dependencias y en ningún caso para el tráfico de escaneo.

| Máquina | Dirección | Función |
|---|---|---|
| Kali Linux | 192.168.56.10 | Máquina atacante, ejecución de la herramienta |
| Metasploitable 2 | 192.168.56.20 | Objetivo Linux con servicios y banners identificables |
| Ubuntu Server mínima | 192.168.56.30 | Objetivo Linux con reglas de cortafuegos controladas |
| Windows 10 | 192.168.56.40 | Objetivo Windows para la diferenciación de sistema operativo |

El objetivo dotado de cortafuegos expone de forma deliberada los tres estados que la herramienta
debe discriminar: un puerto con servicio en escucha, un puerto sin servicio ni regla asociada, y un
puerto sometido a una regla de descarte silencioso. Metasploitable 2 cumple una función
complementaria y no intercambiable: al tratarse de un sistema deliberadamente vulnerable y
desactualizado, ofrece un catálogo de servicios con banners ricos e identificables que resulta
idóneo para las pruebas de fingerprinting, mientras que añadirle reglas de filtrado enturbiaría ese
escenario.

El conjunto requiere aproximadamente nueve gigabytes de memoria con todas las máquinas en ejecución
simultánea. De no disponerse, las pruebas pueden ejecutarse por tandas sin menoscabo de su validez,
al ser el direccionamiento estático y por tanto estable entre sesiones.

---

## 011 — Máquina de ejecución de la herramienta

Quedaba por decidir desde qué sistema se desarrolla y se ejecuta la herramienta: el anfitrión
Windows o la máquina virtual Kali Linux.

En Linux, el acceso a sockets en crudo es nativo y no exige más que privilegios elevados. En
Windows depende del controlador Npcap y arrastra limitaciones conocidas, particularmente en el
envío de tramas en capa de enlace, que es precisamente lo que necesita el ARP Ping. A ello se suma
que Kali incorpora de serie el instrumental necesario para verificar el comportamiento de la
herramienta —nmap como referencia, y tcpdump y Wireshark para inspeccionar el tráfico generado y
depurar los paquetes construidos—, y que ejecutar desde una máquina Linux reproduce con mayor
fidelidad el escenario real de un pentesting interno.

**El desarrollo y la ejecución se realizan sobre la máquina virtual Kali Linux.** Se acepta que la
herramienta queda validada únicamente sobre Linux: su ejecución en Windows es teóricamente posible
con Npcap instalado, pero no se prueba ni se garantiza, y así se hace constar entre las
limitaciones del trabajo.

---

## Consideraciones éticas y legales

Todas las pruebas se ejecutan contra infraestructura propia, desplegada en un segmento virtual
aislado y sin encaminamiento hacia ninguna red externa. En ningún momento del desarrollo ni de la
validación se dirige tráfico contra sistemas de terceros.

El marco normativo aplicable comprende los artículos 197 bis y 264 del Código Penal español,
relativos respectivamente al acceso no autorizado a sistemas de información y a los daños
informáticos, así como el Reglamento General de Protección de Datos en lo que resulte de
aplicación. El aislamiento del laboratorio no responde únicamente a una exigencia metodológica de
reproducibilidad, sino también a la necesidad de garantizar que ninguna de las técnicas
implementadas alcance sistemas sobre los que no se ostenta autorización. Este apartado se desarrolla
como sección propia en la memoria.
