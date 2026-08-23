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
## 012 — Mecanismo de filtrado del escenario de pruebas

El escenario de validación exige que la máquina Ubuntu Server presente simultáneamente los tres
estados que la herramienta debe discriminar: un puerto abierto, uno cerrado y uno filtrado. El
tercero requiere una regla de cortafuegos, y la máquina se encontraba ya en el segmento aislado,
sin salida a internet y sin ninguna herramienta de filtrado instalada, pues el perfil *minimal* de
Ubuntu Server no incluye ni `iptables` ni `nftables`.

Se valoraron cuatro vías. La primera era emplear `nftables`, opción preferible sobre el papel: en
Ubuntu moderno `iptables` no es sino una fachada sobre esa misma infraestructura, y el paquete
`nftables` aporta persistencia nativa mediante `/etc/nftables.conf` y su propio servicio, lo que
habría evitado instalar un paquete adicional para conservar las reglas. La segunda, `iptables`
acompañado de `iptables-persistent`. La tercera, reaplicar las reglas manualmente al inicio de cada
sesión de trabajo, sin persistencia alguna. La cuarta, emplear la imagen ISO de instalación como
repositorio local de paquetes, lo que habría permitido resolver la carencia sin conectar la máquina
a ninguna red.

Los criterios aplicados fueron la persistencia de las reglas entre reinicios, la reproducibilidad
del escenario por un tercero, y la disponibilidad de la herramienta sin acceso a la red. La tercera
vía quedó descartada de inmediato por el primer criterio: una regla que hubiera de reaplicarse a
mano introduce la posibilidad de que una medición se ejecute sobre un escenario incompleto sin que
nadie lo advierta, lo que comprometería silenciosamente los resultados. La cuarta se descartó tras
comprobar que la imagen *live server* de Ubuntu distribuye un sistema de ficheros `squashfs` y no
un conjunto de paquetes utilizable mediante `apt-cdrom`. Y la primera, la preferible, quedó
descartada al verificarse que `nft` tampoco estaba instalado en el sistema.

**Se emplea `iptables` junto con `iptables-persistent`.** Conviene dejar constancia explícita de que
la vía basada en `nftables` no se descartó por criterio técnico sino por indisponibilidad: de haber
estado presente en la instalación, habría sido la elegida.

La decisión obligó a una segunda conexión temporal de la máquina a NAT para instalar ambos
paquetes, con su correspondiente reversión verificada. Dos elecciones de configuración
complementarias se derivan de este mismo escenario y quedan aquí recogidas por su estrecha
relación. La regla emplea `DROP` y no `REJECT`, porque el estado *filtrado* se infiere de la
ausencia de respuesta y un `REJECT` devolvería un mensaje ICMP de inalcanzable, produciendo un
estado distinto e invalidando el escenario para las pruebas de ACK Scan. Y la política por defecto
de la cadena de entrada permanece en `ACCEPT`, ya que con política `DROP` los tres puertos
responderían de forma idéntica y el escenario perdería por completo su capacidad de discriminar
entre un puerto cerrado y uno filtrado.

---

## 013 — Modelo de señales para la detección de sistema operativo

La diferenciación entre sistemas Windows y Linux es el sexto requisito del enunciado y, de los
seis, el único cuya resolución no es determinista: no existe una respuesta del sistema objetivo que
declare su naturaleza, sino un conjunto de indicios que deben combinarse. El diseño de ese conjunto
ha sido el elemento del proyecto con mayor recorrido experimental, y ha requerido dos revisiones
sucesivas motivadas por mediciones del propio laboratorio.

### Modelo inicial y su falsación

El planteamiento original contemplaba tres señales: el tiempo de vida de los paquetes de respuesta,
que los sistemas Windows inicializan en 128 y los Linux en 64; el tamaño de la ventana TCP
anunciada en el SYN/ACK; y la presencia de los puertos 139 y 445, asociados a SMB. Dos de las tres
resultaron no ser válidas tal como estaban formuladas.

La señal basada en SMB se retira por completo. La propia Metasploitable del laboratorio ejecuta
Samba y expone los puertos 139 y 445 en TCP, además de los 137 y 138 en UDP, de modo que su firma
de puertos resulta indistinguible de la de un sistema Windows. Un servicio SMB en escucha indica
que el host habla ese protocolo, no que ejecute Windows. Su ausencia resulta, paradójicamente, más
informativa que su presencia.

La señal basada en el tamaño de ventana se degrada. La medición con `tcpdump` sobre el tráfico real
demostró que ante el SYN mínimo que envía `nmap -sS` —que anuncia únicamente la opción `mss`— tanto
Ubuntu Server como Windows 10 responden con un valor idéntico de 64240. La señal solo discrimina
cuando la sonda anuncia un juego completo de opciones, caso en el que Ubuntu responde 65160 y
Windows 65535.

### Señales validadas experimentalmente

La medición con `tcpdump` ante una misma sonda con opciones completas arrojó las siguientes
diferencias entre los dos sistemas:

| | Ubuntu Server | Windows 10 |
|---|---|---|
| Tiempo de vida | 64 | 128 |
| Ventana en SYN/ACK | 65160 | 65535 |
| Opciones TCP | `mss, sackOK, TS, nop, wscale` | `mss, nop, wscale, nop, nop, sackOK` |
| Marcas de tiempo TCP | Sí | No |
| Longitud del datagrama | 60 | 52 |

De ahí resulta el modelo definitivo, con cinco señales utilizables y un peso asignado a cada una:

| Señal | Peso | Fundamento |
|---|---|---|
| Tiempo de vida 128 frente a 64 | Alto | Medido sobre el cable; alterable, pero infrecuente en la práctica |
| Ausencia de marcas de tiempo TCP | Alto | Señal binaria, no numérica; Windows no las habilita de serie |
| Orden de las opciones TCP | Alto | Firma de pila al estilo *p0f*; Linux sitúa `sackOK` en segunda posición, Windows lo relega tras rellenos `nop` |
| Puerto 135 en escucha | Medio | Asignador de extremos RPC de Microsoft; Samba no lo implementa, de modo que discrimina frente a Metasploitable |
| Puertos en escucha a partir de 49152 | Medio | Rango efímero de Windows, frente al rango 32768–60999 de Linux |
| Tamaño de ventana con sonda completa | Bajo | 65160 frente a 65535; inservible con sonda mínima |

### Decisión

**Se adopta el modelo de cinco señales anterior, con dos consecuencias de diseño que condicionan la
implementación.**

La primera es que la sonda de detección de sistema operativo **debe anunciar un juego completo de
opciones TCP** —`mss`, `sackOK`, marcas de tiempo y escala de ventana—, y no una sonda mínima como
la que emplea `nmap -sS`. Con una sonda pelada se pierden dos de las tres señales de pila, ya que
ni el tamaño de ventana discrimina ni las opciones del SYN/ACK reflejan diferencias apreciables.
No se trata, por tanto, de una preferencia de implementación sino de una condición necesaria para
que el requisito sea resoluble.

La segunda es que el resultado **se expresa como un nivel de confianza y no como una afirmación
categórica**. Ninguna de las señales es concluyente por sí sola: el tiempo de vida puede alterarse,
los puertos característicos dependen de los servicios en ejecución y la firma de opciones puede
variar entre versiones de una misma pila. Combinar cinco indicios ponderados y declarar el grado de
certeza resultante es más honesto y más defendible que emitir un veredicto binario.

### Consecuencias asumidas

El modelo no ofrece garantía absoluta, y así debe reflejarse en las conclusiones. A cambio, el
recorrido seguido constituye material de primer orden para el capítulo de casos de prueba: dos
señales descartadas con evidencia obtenida del propio laboratorio y tres sustitutas validadas
mediante medición directa sobre el cable. Metasploitable 2 se incorpora al banco de pruebas como
**caso adverso deliberado**: un sistema Linux con SMB en escucha que la herramienta debe clasificar
correctamente pese a presentar una firma de puertos característica de Windows.

---

## 014 — Criterio de acierto en la comparación con la herramienta de referencia

La hipótesis del trabajo afirma que la herramienta alcanza una precisión equivalente a la de nmap.
Contrastarla exige definir con precisión qué se cuenta como acierto, y la captura de datos de
referencia reveló que la cuestión dista de ser trivial por dos motivos concretos.

El primero es que nmap **no siempre devuelve versiones exactas**, sino rangos. Sobre el laboratorio
identifica el servicio SMB de Metasploitable como `Samba 3.X - 4.X` y su gestor de bases de datos
como `PostgreSQL 8.3.0 - 8.3.7`. El segundo es que **normaliza el formato de los banners**: la
cadena que efectivamente viaja por la red, `SSH-2.0-OpenSSH_10.2p1 Ubuntu-2ubuntu3`, aparece en su
salida como `OpenSSH 10.2p1 Ubuntu 2ubuntu3`, con los guiones bajos y los guiones sustituidos por
espacios.

Comparar cadenas literales entre ambas salidas produciría por tanto **falsos negativos derivados
únicamente de diferencias de formato**, que nada dicen sobre la capacidad real de la herramienta.

### Decisión

**La referencia primaria de la medición es la verdad-terreno del laboratorio, no la salida de
nmap.** Esta precisión es determinante: nmap es una herramienta de comparación, no un oráculo. Su
salida se contrasta contra la misma referencia que la de Melmapo, lo que permite que ambas
herramientas acierten, fallen o difieran, y que esas diferencias se interpreten sin presuponer cuál
de las dos tiene razón.

Sobre esa base se establecen tres criterios según la naturaleza del dato evaluado.

**Estados de puerto.** La comparación es exacta y binaria. El estado declarado —abierto, cerrado o
filtrado— coincide o no coincide con el estado real conocido. No caben coincidencias parciales.

**Sistema operativo.** Se considera acierto que la familia declarada, Windows o Linux, coincida con
la real. El nivel de confianza asociado se registra pero no penaliza el cómputo de aciertos: se
analiza por separado, como indicador de la calibración del modelo.

**Servicio y versión.** Se aplica una clasificación en tres niveles, previa normalización de ambas
cadenas mediante conversión a minúsculas, sustitución de guiones bajos y guiones por espacios, y
colapso de espacios consecutivos.

- **Acierto exacto:** el producto coincide y la versión coincide con la real tras la normalización.
- **Coincidencia parcial:** el producto coincide pero la versión no se determina con exactitud.
  Se incluyen aquí los casos en que la versión real queda comprendida dentro de un rango declarado,
  y aquellos en que se identifica el producto sin versión alguna.
- **Fallo:** el producto declarado difiere del real, o la versión declarada es incompatible con
  este.

### Consecuencias asumidas

La clasificación en tres niveles obliga a presentar los resultados con mayor detalle que una simple
tasa de acierto, pero es la única forma de que la comparación resulte informativa. Merece la pena
señalar una consecuencia que el planteamiento inicial no permitía apreciar: al medir ambas
herramientas contra la misma verdad-terreno, es posible que Melmapo obtenga un **acierto exacto**
allí donde nmap solo alcanza una **coincidencia parcial**, como ocurre en los servicios para los
que la referencia devuelve rangos. La hipótesis se formuló en términos de equivalencia, de modo que
un resultado superior en algún indicador concreto no la refuta; simplemente la supera, y así debe
discutirse.

Los criterios aquí fijados deben aplicarse de forma idéntica a ambas herramientas y declararse
explícitamente en el capítulo de casos de prueba, de manera que un tercero pueda reproducir el
cómputo a partir de las salidas en crudo.

---

## 015 — Quinto estado de puerto
 
El diseño inicial contemplaba cuatro estados de puerto: abierto, cerrado, filtrado
y no filtrado. Los tres primeros son los que el enunciado exige discriminar; el
cuarto lo requiere el ACK Scan, que no determina si un puerto está abierto sino si
un cortafuegos con estado se interpone en el camino.
 
Al abordar el escaneo y el descubrimiento sobre UDP se advirtió que ese conjunto
resulta insuficiente. UDP carece de saludo, de modo que un datagrama dirigido a un
puerto abierto no genera necesariamente respuesta alguna: el servicio puede
limitarse a procesarlo en silencio. La ausencia de respuesta es por tanto
compatible con dos situaciones que la herramienta no puede distinguir con la
información de que dispone, a saber, que el puerto esté abierto y su servicio no
conteste, o que un cortafuegos descarte el tráfico.
 
Se valoraron tres salidas. La primera, clasificar como filtrado todo lo que no
responda, que produciría falsos negativos sistemáticos sobre servicios UDP
silenciosos. La segunda, clasificarlo como abierto, que produciría el error
simétrico y, siendo el más frecuente en la práctica el filtrado, en mayor número.
La tercera, declarar la ambigüedad como tal.
 
**Se incorpora un quinto estado, `ABIERTO_FILTRADO`.** La solución coincide con la
que adopta nmap, lo que además facilita la comparación de resultados entre ambas
herramientas.
 
La consecuencia asumida es que la salida resulta menos rotunda: en lugar de un
veredicto para cada puerto, algunos quedan expresamente sin resolver. Se considera
preferible a fabricar una certeza que la técnica no sostiene, y guarda coherencia
con el tratamiento que la decisión 013 da al resultado de la detección de sistema
operativo, expresado como nivel de confianza y no como afirmación categórica. El
riesgo relativo a la ambigüedad del descubrimiento por UDP queda con ello atendido
en el plano del modelo de datos, si bien su comportamiento real debe comprobarse
en las pruebas correspondientes.
 
---
 
## 016 — Limitador de concurrencia
 
La decisión 006b fijó `ThreadPoolExecutor` como modelo único de concurrencia. Al
implementar el escaneo se advirtió que esa decisión, por sí sola, no basta.
 
La paralelización se produce en dos niveles. El orquestador reparte los objetivos
entre hilos, y cada fase reparte a su vez los puertos de un mismo objetivo. Ambos
niveles leen el mismo parámetro de configuración, de modo que una ejecución con
cincuenta trabajadores abriría cincuenta hilos de objetivos, cada uno con
cincuenta hilos de puertos: dos mil quinientas operaciones de red simultáneas. El
efecto no es solo el agotamiento de descriptores de fichero del proceso. Es, sobre
todo, que la saturación de la pila de red introduce demoras que se atribuirían
erróneamente a los objetivos, falseando las mediciones de latencia sobre las que
se apoya la comparación de tiempos.
 
Se consideraron tres alternativas. Repartir el parámetro entre ambos niveles
—asignando la raíz cuadrada a cada uno, por ejemplo— resulta poco predecible y
difícil de explicar. Eliminar la paralelización de uno de los niveles simplifica
el problema pero desaprovecha el paralelismo en el escenario contrario al elegido:
suprimirla en los puertos penaliza el escaneo de un único objetivo, y suprimirla
en los objetivos penaliza el barrido de un segmento. La tercera consiste en
mantener ambos niveles y acotar el total.
 
**Se incorpora un semáforo compartido que acota el número total de operaciones de
red en vuelo**, con independencia del nivel desde el que se inicien. El límite
coincide con el número de trabajadores configurado, de modo que el parámetro
recupera el significado que el operador le atribuye: el máximo de operaciones
simultáneas.
 
Una precisión sobre su uso, necesaria para justificar que el diseño es seguro: el
semáforo se adquiere únicamente alrededor de la operación de red y se libera en
todos los casos, incluidos los de error, mediante una cláusula de finalización.
Nunca se mantiene adquirido mientras un hilo espera el resultado de otro. Esa
condición es la que impide el interbloqueo que un semáforo compartido entre dos
niveles de paralelismo podría producir en caso contrario.
 
Esta decisión amplía la 006b, no la sustituye.
 
---
 
## 017 — Combinación de las técnicas de descubrimiento
 
Al integrar las técnicas de descubrimiento hubo que decidir si detener el sondeo
de un objetivo en cuanto una de ellas confirma que está activo, o ejecutarlas
todas y registrar cuáles responden.
 
La primera opción es más rápida: en un segmento donde la mayoría de los equipos
responde al eco ICMP, el resto de técnicas no llegaría a ejecutarse. La segunda
cuesta más tiempo, pero produce un dato que la primera destruye, a saber, qué
técnicas responden en qué equipos.
 
Ese dato no es accesorio. El enunciado exige implementar cuatro técnicas de
descubrimiento, y la justificación de por qué hacen falta cuatro y no una descansa
precisamente en que cada una acierta donde las demás fallan. Con la primera opción
esa afirmación solo podría sostenerse por remisión a la literatura; con la segunda,
se sostiene con medidas del propio laboratorio.
 
**Se ejecutan todas las técnicas solicitadas sobre cada objetivo y se registra la
lista de las que obtuvieron respuesta.** El operador conserva el control del coste
mediante la selección de técnicas, de modo que quien busque rapidez puede solicitar
una sola.
 
Se asume el mayor coste temporal, acotado en cualquier caso por el número de
técnicas seleccionadas, que no supera cuatro. El registro de las técnicas
respondidas se incorpora al modelo de datos y a ambas salidas.

---

---

## 018 — Uso de envío por lotes en las técnicas basadas en paquetes en crudo

La primera implementación del escaneo por saludo parcial —requisito 2— empleó el patrón habitual
del escaneo por conexión completa: un pool de hilos, uno por puerto, cada uno invocando `sr1` de
Scapy y esperando su respuesta antes de emitir el siguiente. El código pasaba las pruebas unitarias
—que sustituían Scapy por un doble— y funcionaba correctamente contra un único puerto. Al
ejecutarlo contra el laboratorio con siete puertos, los siete se declararon como filtrados en tres
ejecuciones consecutivas, resultado que la verdad-terreno del apartado 6.3 refutaba
inmediatamente.

El diagnóstico se realizó siguiendo la disciplina en cuatro pasos que se ha adoptado desde entonces
como convención del proyecto: reducción a caso mínimo —un puerto y un hilo, veredicto correcto—,
contraste con la técnica alternativa —conexión completa, seis puertos abiertos—, instrumentación
con `tcpdump` filtrando solo el tráfico relevante, y aislamiento de Scapy con un script de tres
líneas. La captura reveló que la técnica emitía correctamente los siete SYN y recibía sus SYN/ACK,
pero las respuestas no llegaban al hilo que las esperaba. La causa: `sr1` no es seguro entre hilos
—cada llamada abre su propio socket en crudo y filtra el tráfico contra el paquete emitido—, y el
envío del reinicio adicional que aborta cada conexión abierta introduce interferencia con las
llamadas simultáneas de los demás hilos.

Se valoraron dos alternativas para la corrección. La primera consistía en serializar los sondeos
crudos con un cerrojo global: preserva el modelo de un temporizador por puerto —afirmación
temporal del apartado 3.2.4 en su formulación original— pero hace la técnica más lenta que la
conexión completa, resultado contrario a la teoría. La segunda consistía en migrar a envío por
lotes con `sr`, que despacha la tanda entera y recoge después las respuestas: es la solución que ya
empleaba el barrido ARP con `srp` desde el inicio del proyecto.

**Se adopta el envío por lotes**. Se aplica al saludo parcial y también al escaneo ACK —requisito
3—, pese a que este último funcionaba correctamente con el modelo original, para que la
comparativa de tiempos del capítulo sexto no midiera una diferencia de implementación en lugar de
una diferencia de técnica.

La decisión tiene una consecuencia sobre la afirmación del apartado 3.2.4, que hubo de ser
reformulada. La formulación original —«el coste depende del número de puertos filtrados, no de los
examinados»— era cierta bajo el modelo de un temporizador por puerto, pero deja de serlo con
envío por lotes: todos los puertos que no responden agotan un único temporizador compartido, de
modo que basta un solo puerto filtrado para que la exploración deba aguardar a que expire el plazo
completo. La formulación revisada describe esta asimetría como propiedad del protocolo y no como
consecuencia de la implementación, y se verifica experimentalmente en el subapartado 6.5.2 con las
mediciones sobre los tres hosts del laboratorio.

---

## 019 — Aleatorización del puerto de origen en las sondas crudas

La captura de tráfico realizada durante el diagnóstico de la decisión 018 reveló un detalle
adicional: Scapy fija por defecto el puerto de origen al 20 —FTP data— cuando se construye un
segmento TCP sin especificar el campo `sport`. Un cortafuegos con reglas heredadas para tráfico
FTP podría tratar ese puerto de manera especial —por ejemplo, permitiendo el retorno de
conexiones—, lo que falsearía los resultados de una exploración legítima.

Las alternativas consideradas eran mantener el valor por defecto de Scapy y documentar la
limitación; fijar un puerto arbitrario elegido por el proyecto; o tomar uno del rango efímero como
hacen las herramientas de referencia. La primera contamina las mediciones sin necesidad. La
segunda produce una firma reconocible que un dispositivo de detección de intrusiones podría
aprovechar. La tercera imita el comportamiento de un cliente legítimo y evita ambos problemas.

**Se elige un puerto del rango efímero**, entre 32768 y 60999 —los límites que emplea Linux por
defecto—, una vez por tanda de envío. La variación paquete a paquete impediría a Scapy emparejar
cada respuesta con la sonda que la provocó, motivo por el que el puerto se mantiene constante
dentro de una misma tanda y se renueva entre tandas.

La consecuencia es doble: se elimina una posible fuente de falseo en las mediciones —presencia de
reglas heredadas para FTP en el objetivo— y se reduce la firma característica del tráfico emitido
por la herramienta, aunque este último efecto queda parcialmente contrarrestado por la propia
estructura del envío por lotes, que resulta reconocible con independencia del puerto de origen.

---

## 020 — Estrategia de identificación de servicios: leer antes que estimular

Los requisitos 4 y 5 del enunciado —obtención de versión por banner y por cabeceras HTTP— exigen
distinguir cuándo un servicio se declara espontáneamente al establecerse la conexión y cuándo
requiere ser interrogado. Se valoraron dos estrategias contrapuestas.

La primera consistía en enviar una sonda genérica —una petición HTTP `GET`— a todo puerto abierto,
leer la respuesta y clasificar. Es simple de implementar y no requiere lógica por protocolo. La
segunda, en conectar al puerto, leer durante un plazo corto lo que el servicio emita por
iniciativa propia, y estimular solo aquellos puertos que no hayan dicho nada en el paso anterior.

Un análisis somero revela que la primera alternativa produce ruido innecesario en las trazas de
los servicios que ya iban a declararse por sí solos —SSH y SMTP, por ejemplo, registran una
petición HTTP como intento de acceso malformado— y, en el caso de protocolos binarios como MySQL,
provoca el cierre de la conexión antes de haber leído el saludo. Adicionalmente, el propio
apartado 3.4.2 de la memoria describe el mecanismo en el orden inverso al de esta alternativa:
primero los servicios que emiten mensaje de bienvenida, después los que exigen estímulo.

**Se adopta la estrategia de lectura primero y estímulo después.** El módulo de banner —requisito
4— se limita a leer al conectar y clasifica el puerto como no identificado si el servicio no
emite nada. El módulo de HTTP —requisito 5— se aplica en segunda instancia solo a los puertos que
hayan quedado sin identificar, con una petición mínima `GET / HTTP/1.0`. La cascada se realiza
dentro de la fase de fingerprinting sin intervención del operador.

Se asume una consecuencia menor: los servicios de protocolo binario que no emitan una cadena
legible al conectar —SMB, NetBIOS, telnet con negociación de opciones— quedan sin identificar. La
alternativa habría exigido implementar un catálogo de sondas específicas por protocolo, tarea que
excede el alcance del trabajo y que se recoge como línea futura en el capítulo séptimo.

---

## 021 — Doble fuente de tiempo de vida en la detección de sistema operativo

La primera ejecución del módulo de detección de sistema operativo —requisito 6, decisión 013—
contra el laboratorio devolvió el veredicto Windows para Metasploitable con confianza del 60 %.
El sistema es Linux con firma SMB señuelo, según se documentó en el apartado 6.3, y la
clasificación errónea era el caso adverso deliberado que el modelo debía resolver correctamente.

El análisis del fichero JSON de salida reveló la causa. La señal de tiempo de vida —la de mayor
peso del modelo, con peso 4 sobre 15— aparecía como `null` en los tres hosts. En el escenario
prioritario del trabajo, auditoría interna sobre un segmento local, el descubrimiento se resuelve
por resolución en capa de enlace —ARP— en todos los objetivos, y la fase ICMP no llega a
ejecutarse. La señal de mayor peso del modelo quedaba ausente precisamente en el escenario que la
memoria prioriza.

Se identificaron tres opciones. La primera consistía en modificar la firma del modelo para que la
ausencia de marcas de tiempo TCP no puntuase en contra —Metasploitable las omite pero también lo
haría un Linux moderno con esa opción desactivada—. La segunda, en aceptar la clasificación
errónea y explicarla en la memoria como límite del modelo sobre pilas anteriores a 2010. La
tercera, en obtener el tiempo de vida de la respuesta a la sonda de pila que el módulo ya emite,
en lugar de depender exclusivamente del ICMP.

Las dos primeras exigían modificar el modelo *a posteriori* a partir del resultado observado,
práctica que invalida cualquier validación empírica. La tercera reutilizaba información que ya
circulaba por el código y resolvía el problema estructural sin ajustar el modelo.

**Se adopta la tercera opción: doble fuente del tiempo de vida.** El módulo prefiere el observado
por el descubrimiento por ICMP —fase específicamente diseñada para observarlo, con validación por
dirección de origen tras el cierre de R-41— cuando esté disponible, y aprovecha el de la respuesta
a la sonda de pila cuando el ICMP no lo aportó. La procedencia se anota en el diccionario de
señales del resultado, en la forma `64 (icmp) → linux` o `64 (sonda_pila) → linux`, para que
cualquier veredicto sea auditable.

El resultado sobre el laboratorio pasa de Windows con 60 % a Linux con 57 %, veredicto correcto
que refleja fielmente la ambigüedad real del caso adverso —firma parcial con Windows moderno— sin
ocultarla ni ajustar el modelo a conveniencia.

---

## 022 — Umbral de identificación de servicio

Al ejecutar por primera vez la cascada de identificación de servicios contra el laboratorio, el
puerto 3306 de Metasploitable quedaba sin identificar pese a que la extracción heurística sobre su
banner aislado devolvía la versión correcta. El diagnóstico reveló tres causas concurrentes que
compartían un mismo origen: el criterio con que la clase `Servicio` del modelo de datos declara
que un puerto ha sido identificado.

La primera implementación del método `esta_identificado()` devolvía cierto únicamente cuando el
campo `nombre` estaba asignado. Un banner del que la extracción heurística obtenía versión pero
del que no se podía derivar nombre —caso de MySQL, cuyo saludo binario contiene la cadena
`5.0.51a-3ubuntu5` pero no una marca reconocible sin un caso especial— se declaraba no
identificado. La cascada del fingerprint, al considerarlo no identificado, volvía a sondearlo con
HTTP; MySQL respondía con basura binaria y un mensaje `Bad handshake`, y esa respuesta terminaba
sobreescribiendo la información previa.

**Se adopta un criterio más laxo:** un servicio se declara identificado si conoce su nombre o su
versión, entendiendo que ambas atribuyen información al puerto que un sondeo posterior no
aportaría. La modificación se acompaña de dos cambios de refuerzo en la cascada: el patrón MySQL
atribuye la marca a partir de la identidad del patrón que coincidió —con prioridad para MariaDB
cuando aparece explícitamente en el banner—, y el módulo HTTP preserva el servicio existente si
la respuesta recibida no es HTTP, en lugar de sobreescribirlo con la envoltura vacía que producía
antes.

Las tres correcciones se realizan en un único cambio, por ser tres facetas del mismo problema. La
prueba de aceptación consiste en la ejecución contra Metasploitable, que pasa de mostrar el 3306
sin identificar a mostrarlo como MySQL 5.0.51a-3ubuntu5, veredicto verificable en el apartado
6.5.4 de la memoria.

Se asume una consecuencia: puede haber otros protocolos binarios cuya versión se extraiga
correctamente sin nombre reconocido, y en ese caso el nombre quedará ausente en la salida. La
política del proyecto —conservar el `banner_bruto` en todos los casos— permite que el auditor
compruebe la naturaleza del servicio a partir de la evidencia bruta cuando la extracción
heurística no baste.

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
