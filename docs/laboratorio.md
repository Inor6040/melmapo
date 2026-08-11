# Laboratorio de pruebas

Documento de despliegue del entorno controlado sobre el que se valida Melmapo. Todas las pruebas
del trabajo se ejecutan exclusivamente contra estas máquinas, en un segmento virtual aislado sin
encaminamiento hacia ninguna red externa.

El procedimiento recoge las incidencias encontradas durante el despliegue real. No es una guía
teórica: cada advertencia responde a un problema que se produjo y que conviene anticipar para que
un tercero pueda reproducir el entorno sin repetirlos.

## Composición

| Máquina | Dirección | MAC | Función |
|---|---|---|---|
| Kali Linux | 192.168.56.10 | `00:0c:29:dd:39:d9` | Máquina atacante |
| Metasploitable 2 | 192.168.56.20 | `00:0c:29:20:b5:39` | Objetivo Linux con servicios y banners identificables |
| Ubuntu Server | 192.168.56.30 | `00:0c:29:01:3f:68` | Objetivo Linux con reglas de cortafuegos controladas |
| Windows 10 | 192.168.56.40 | `00:0c:29:5f:57:57` | Objetivo Windows para diferenciación de sistema operativo |
| Adaptador del anfitrión | 192.168.56.1 | `00:50:56:c0:00:02` | No es una máquina del laboratorio; ver nota |

Segmento: `192.168.56.0/24`, sin pasarela predeterminada y sin servidor DHCP.

**Nota sobre el quinto host.** Si el adaptador virtual del anfitrión permanece conectado a VMnet2,
la dirección `192.168.56.1` responde al barrido ARP y el segmento contiene cinco hosts alcanzables,
no cuatro. Debe figurar como host legítimo esperado en la tabla de referencia del capítulo de
casos de prueba: de lo contrario, la herramienta lo detectará correctamente y ese acierto se
contabilizará como falso positivo, distorsionando la medición de precisión.

---

## 1. Segmento virtual en VMware Workstation

Abrir el **Editor de red virtual** (menú *Edit → Virtual Network Editor*). En Windows requiere
elevación: pulsar *Change Settings* si los controles aparecen deshabilitados.

1. *Add Network* → seleccionar **VMnet2**.
2. Marcar **Host-only**.
3. **Desmarcar** *Use local DHCP service to distribute IP addresses*. El direccionamiento estático
   es lo que garantiza que las pruebas sean reproducibles entre sesiones.
4. *Subnet IP*: `192.168.56.0`. *Subnet mask*: `255.255.255.0`.
5. Aplicar y aceptar.

La casilla *Connect a host virtual adapter to this network* determina si el anfitrión participa en
el segmento. Dejarla marcada facilita la depuración y permite recuperar ficheros desde el navegador
del anfitrión, pero tiene dos consecuencias que deben asumirse conscientemente: añade un quinto
host al barrido ARP, y crea una ruta entre el equipo del autor y una máquina deliberadamente
vulnerable. Ambas se recogen en las consideraciones éticas.

---

## 2. Asignación de adaptadores

En *VM → Settings → Network Adapter* de cada máquina:

- **Kali**: dos adaptadores. El primero en **NAT**, empleado únicamente para instalar dependencias.
  El segundo en **Custom: VMnet2**, que es el que transporta todo el tráfico de escaneo.
- **Metasploitable 2, Ubuntu Server y Windows 10**: un único adaptador en **Custom: VMnet2**.

**Norma sobre Metasploitable 2.** Esta máquina **no se conecta nunca a NAT ni a ninguna red con
salida a internet**. Se trata de un sistema deliberadamente vulnerable, con servicios sin parchear,
credenciales por defecto y puertas traseras conocidas. La excepción temporal admitida para Kali y
para Ubuntu Server no le resulta aplicable en ningún caso. Conviene verificar explícitamente que
conserva un único adaptador asignado a VMnet2.

---

## 3. Kali Linux (192.168.56.10)

Identificar el interfaz correspondiente a VMnet2. Con dos adaptadores, el de NAT suele ser `eth0`
y el del laboratorio `eth1`:

```bash
ip -brief address
```

Asignar dirección estática **sin pasarela predeterminada**. Definir una pasarela en este interfaz
rompería la salida a internet del adaptador NAT:

```bash
sudo nmcli connection add type ethernet ifname eth1 con-name lab \
  ipv4.method manual ipv4.addresses 192.168.56.10/24 ipv6.method disabled
sudo nmcli connection up lab
```

Verificar que la ruta por defecto sigue apuntando al adaptador NAT:

```bash
ip route show default
```

Instalar las dependencias de desarrollo y de verificación:

```bash
sudo apt update
sudo apt install -y python3-pip python3-venv tcpdump wireshark nmap git arp-scan
```

Comprobar que Scapy opera con privilegios elevados antes de dar por cerrada la máquina:

```bash
sudo python3 -c "from scapy.all import *; print(sr1(IP(dst='192.168.56.30')/ICMP(), timeout=2).summary())"
```

---

## 4. Metasploitable 2 (192.168.56.20)

Credenciales por defecto: `msfadmin` / `msfadmin`.

La imagen se distribuye preconstruida y no requiere instalación desde cero. Deben conservarse los
ficheros `.vmdk`, `.vmx`, `.nvram` y `.vmsd`.

### Direccionamiento

El sistema es una Ubuntu 8.04 y utiliza el esquema clásico de configuración de red. Copiar el
fichero antes de modificarlo:

```bash
sudo cp /etc/network/interfaces /etc/network/interfaces.bak
```

Editar `/etc/network/interfaces`:

```
auto eth0
iface eth0 inet static
    address 192.168.56.20
    netmask 255.255.255.0
```

No se define pasarela ni servidores de nombres. Aplicar:

```bash
sudo /etc/init.d/networking restart
```

Confirmar que no existe ruta por defecto:

```bash
route -n
```

### Trabajo en la consola

La consola de la máquina presenta tres limitaciones que conviene resolver antes de capturar datos.
Ninguna de las técnicas siguientes modifica el estado del sistema, condición necesaria para no
alterar el estado inicial que se congelará en la instantánea:

- **Distribución de teclado inglesa.** `loadkeys es` la corrige en memoria.
- **Ausencia de desplazamiento.** La salida larga no cabe en pantalla. `script -a fichero` graba la
  sesión completa para consultarla después.
- **Extracción de ficheros.** `python -m SimpleHTTPServer 8000` sobre `/tmp` permite recuperar la
  grabación desde el navegador del anfitrión.

No debe emplearse `nc -w` con redirección para capturar banners: la versión de netcat incluida no
cierra la conexión al agotarse la entrada y deja la sesión colgada sin mostrar el banner.

### Servicios expuestos

La máquina se emplea tal cual, con su catálogo de servicios desactualizados, que es precisamente lo
que la hace útil para las pruebas de obtención de versiones por banner. Expone de serie FTP (21),
SSH (22), Telnet (23), SMTP (25), HTTP (80), RPC (111), NetBIOS (137 y 138 en UDP), SMB (139 y
445), MySQL (3306) y PostgreSQL (5432), entre otros.

Dos particularidades con efecto directo sobre la medición:

- **Puertos dinámicos.** Los correspondientes a `rpc.mountd`, `rpc.statd` y `rmiregistry` los
  asigna `portmap` en cada arranque y cambian tras un reinicio. No deben figurar como valores fijos
  en la tabla de referencia.
- **Zócalos solo en IPv6.** Los puertos 22, 2121, 3632 y 5432 aparecen únicamente como `tcp6`. Con
  `bindv6only` desactivado, comportamiento por defecto en Linux, un zócalo en `::` acepta también
  conexiones IPv4 mediante direcciones mapeadas, de modo que el escaneo IPv4 los ve abiertos.

---

## 5. Ubuntu Server (192.168.56.30)

Instalación con perfil **minimal**, sin entorno gráfico, marcando durante la instalación
únicamente el servidor OpenSSH.

### Advertencias previas

El perfil *minimal* es considerablemente más escueto de lo que cabría suponer, y la máquina se
instala directamente en el segmento aislado, sin salida a internet. Conviene conocer estas
carencias antes de empezar:

- **No incluye editor de texto ni `ping`.** No hay `nano`, `vi`, `vim` ni `iputils-ping`.
- **No incluye herramientas de filtrado.** No hay `iptables` ni `nftables`.

Ambas carencias obligan a una conexión temporal a NAT, descrita más adelante. Se comprobó
previamente la disponibilidad de `nft`, partiendo de que en Ubuntu moderno `iptables` es una
fachada sobre *nftables* y de que el paquete `nftables` aporta persistencia nativa mediante
`/etc/nftables.conf`, lo que habría permitido montar el escenario sin salida a internet. Tampoco
estaba instalado. Se descartó igualmente el uso de la imagen ISO como repositorio local, dado que
la imagen *live server* distribuye un *squashfs* y no un conjunto de paquetes utilizable con
`apt-cdrom`.

### Limitaciones de la consola de VMware

**La consola no admite pegado.** Todo comando ha de teclearse a mano, lo que desaconseja los
bloques multilínea. Un *here-document* pegado se aplana en una sola línea y falla; y lo que es
peor, la redirección `>` trunca el fichero antes de fallar, de modo que deja la configuración
vacía. La alternativa segura es escribir línea a línea con `echo ... | sudo tee -a`.

**Copia de seguridad previa.** Antes de modificar cualquier fichero de configuración, copiarlo:

```bash
sudo cp /etc/netplan/00-installer-config.yaml /etc/netplan/00-installer-config.yaml.bak
```

Durante el despliegue real, esta copia fue lo que permitió recuperar el estado tras el fallo del
*here-document*.

### Direccionamiento

Obtener el nombre real del interfaz con `ip -brief address`. El fichero de Netplan debe quedar así:

```yaml
network:
  version: 2
  ethernets:
    ens33:
      dhcp4: false
      addresses: [192.168.56.30/24]
```

Aplicar con `sudo netplan apply`. No se define pasarela ni servidores de nombres.

### Conexiones temporales a NAT

Durante el despliegue fueron necesarias **dos** conexiones temporales a NAT en esta máquina: la
primera para instalar los editores y `ping`, la segunda para instalar `iptables` e
`iptables-persistent`. Conviene planificar la lista completa de paquetes de antemano para no tener
que repetir la operación.

El procedimiento seguro **no consiste en editar el fichero de Netplan original**, sino en añadir
uno temporal de nombre superior. Netplan fusiona el contenido del directorio y la clave del fichero
de nombre mayor prevalece, de modo que la reversión se reduce a borrar el fichero temporal:

```bash
# Crear el fichero temporal
sudo tee /etc/netplan/99-nat.yaml > /dev/null <<'EOF'
network:
  version: 2
  ethernets:
    ens33:
      dhcp4: true
EOF
sudo chmod 600 /etc/netplan/99-nat.yaml

# Punto de control: muestra la configuración fusionada antes de aplicarla
netplan get ethernets

sudo netplan apply
```

Instalar los paquetes necesarios y, a continuación, **revertir en este orden**: primero borrar el
fichero temporal y aplicar la configuración, y solo después conmutar el adaptador de vuelta a
VMnet2. De este modo la máquina no permanece en ningún momento en NAT con una configuración capaz
de salir a internet sin supervisión.

```bash
sudo rm /etc/netplan/99-nat.yaml
sudo netplan apply
# Solo ahora: VM → Settings → Network Adapter → Custom: VMnet2
```

Verificar el aislamiento restaurado con `ping -c 2 8.8.8.8`, que debe devolver *unreachable*.

### Escenario de filtrado

Esta máquina expone deliberadamente los tres estados que la herramienta debe discriminar.

| Puerto | Estado esperado | Configuración |
|---|---|---|
| 22 | Abierto | Servicio OpenSSH en escucha |
| 23 | Cerrado | Sin servicio y sin regla asociada |
| 80 | Filtrado | Regla de descarte silencioso |

```bash
sudo systemctl enable --now ssh
sudo iptables -P INPUT ACCEPT
sudo iptables -A INPUT -p tcp --dport 80 -j DROP
```

Dos elecciones de esta configuración son deliberadas y deben justificarse en la memoria:

- **`DROP` y no `REJECT`.** El estado *filtrado* se infiere de la **ausencia** de respuesta. Un
  `REJECT` devolvería un ICMP de inalcanzable y produciría un estado distinto, invalidando el
  escenario para las pruebas de ACK Scan.
- **Política de entrada en `ACCEPT`.** Con política `DROP` los tres puertos responderían igual y el
  escenario perdería su capacidad de discriminar entre cerrado y filtrado.

Las reglas no persisten tras un reinicio. Para conservarlas:

```bash
sudo apt install -y iptables-persistent
sudo netfilter-persistent save
```

Las reglas son estado del núcleo y no dependen del adaptador conectado, de modo que el escenario
puede montarse mientras la máquina está aún en NAT. Comprobar el resultado:

```bash
sudo iptables -L INPUT -n -v --line-numbers
sudo ss -tulpn
```

**La comprobación decisiva es el reinicio.** Guardar no equivale a persistir: una regla que no
sobreviviera al arranque haría caer el escenario en mitad de las mediciones.

---

## 6. Windows 10 (192.168.56.40)

### Direccionamiento

En PowerShell con privilegios de administrador:

```powershell
Get-NetAdapter
New-NetIPAddress -InterfaceAlias "Ethernet0" -IPAddress 192.168.56.40 -PrefixLength 24
```

Sustituir `Ethernet0` por el nombre real del adaptador. No se define pasarela predeterminada.

### Configuración como objetivo

Esta máquina sirve de contraste frente a los sistemas Linux en la diferenciación de sistema
operativo. No cumple función de escenario de filtrado, papel que corresponde a la máquina Ubuntu.
Se desactiva por tanto el cortafuegos, de modo que las señales empleadas en la inferencia resulten
observables sin interferencias:

```powershell
Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled False
```

Se habilita SMB2:

```powershell
Set-SmbServerConfiguration -EnableSMB2Protocol $true -Force
```

**Sobre la justificación de habilitar SMB.** Es incorrecto afirmar que los puertos 139 y 445 sean
característicos de sistemas Windows y sirvan por sí solos como señal de sistema operativo: la
propia Metasploitable del laboratorio los expone mediante Samba, de modo que un Linux puede
presentar una firma de puertos indistinguible de la de un Windows. Lo que indican esos puertos es
la presencia del protocolo SMB, no del sistema operativo subyacente. La razón correcta para
habilitarlos aquí es **servir de contraste** frente al Linux con Samba, y permitir así comprobar
que la herramienta no confunde ambos casos.

Señal que sí discrimina: el **puerto 135**, asignador de extremos RPC de Microsoft, presente en
Windows y ausente en Metasploitable, que ejecuta Samba pero no implementa ese servicio.

### Comprobaciones y particularidades

Verificar el aislamiento:

```powershell
Get-NetRoute -DestinationPrefix 0.0.0.0/0
```

**Este comando devuelve un error de objeto no encontrado cuando no existe ruta por defecto, y ese
error es el resultado correcto.** No debe interpretarse como un fallo de configuración.

Comprobar los puertos en escucha:

```powershell
netstat -ano | findstr LISTENING
Get-NetTCPConnection -State Listen
```

**Ambas vistas del mismo estado no coinciden.** `Get-NetTCPConnection` muestra el puerto 445
escuchando únicamente en `::`, mientras que `netstat -an` lo muestra en `0.0.0.0` y en `[::]`. La
discrepancia es un buen argumento a favor de validar el estado de los puertos desde la red y no
desde el propio host.

Los puertos del rango efímero, a partir de `49664`, corresponden a servicios RPC. Su numeración es
parcialmente inestable entre reinicios —los servicios que arrancan antes tienden a reutilizar los
mismos números—, por lo que no deben figurar como valores fijos en la tabla de referencia. El
**rango** en sí, a partir de 49152, sí es estable como señal de sistema operativo frente al rango
tradicional de Linux, comprendido entre 32768 y 60999.

Verificar la persistencia de dirección, cortafuegos y configuración SMB tras un reinicio.

---

## 7. Verificación del despliegue

Desde Kali, comprobar en este orden:

```bash
# Conectividad en capa de red
ping -c 2 192.168.56.20
ping -c 2 192.168.56.30
ping -c 2 192.168.56.40

# Resolución en capa de enlace: las tres direcciones MAC deben aparecer
ip neighbour show dev eth1

# Barrido ARP del segmento
sudo arp-scan --interface=eth1 192.168.56.0/24

# Comprobación del escenario de filtrado
sudo nmap -sS -p 22,23,80 192.168.56.30
```

El barrido ARP debe devolver **cinco hosts**: los cuatro del laboratorio más el adaptador virtual
del anfitrión en `192.168.56.1`.

El último comando debe devolver el puerto 22 como abierto, el 23 como cerrado y el 80 como
filtrado. Si el 80 aparece como cerrado en lugar de filtrado, la regla de descarte no está activa;
si los tres aparecen filtrados, la política por defecto de la cadena de entrada no es `ACCEPT`.

Confirmar además que Kali conserva la salida a internet:

```bash
ping -c 2 8.8.8.8
```

**Nota menor.** `arp-scan` puede no disponer de permisos para leer `ieee-oui.txt` ni
`mac-vendor.txt`, en cuyo caso muestra `(Unknown)` en la columna de fabricante. No afecta al
resultado del barrido; nmap sí resuelve el fabricante a partir de la dirección MAC.

---

## 8. Instantáneas

Una vez verificado el despliegue **y una vez incorporadas a este documento todas las correcciones
derivadas de la ejecución real**, tomar una instantánea de cada máquina virtual desde
*VM → Snapshot → Take Snapshot*, con la descripción `estado inicial del laboratorio`.

El orden importa: si se congela el estado antes de documentar el procedimiento que lo produjo, el
documento y el entorno divergen, y la memoria acabaría describiendo un laboratorio distinto del que
generó las mediciones.

Las instantáneas permiten revertir cualquier objetivo a un estado conocido si una prueba lo altera,
y garantizan que las mediciones repetidas parten siempre de las mismas condiciones.

---

## 9. Reproducibilidad: versiones

| Componente | Versión |
|---|---|
| VMware Workstation Pro | 25.0.1.25219725 |
| Kali Linux | 2026.1 (`kali-rolling`) |
| Ubuntu Server | 26.04 LTS (Resolute Raccoon) |
| Metasploitable 2 | Kernel `2.6.24-16-server`, i686, Ubuntu 8.04 |
| Windows 10 | Education `10.0.19045`, compilación 19045, 64 bits |
| Python (Kali) | 3.13.12 |
| nmap | 7.99 |
| Scapy | 2.7.01 |
| arp-scan | 1.10.0 |

---

## Consideraciones éticas y legales

El segmento `192.168.56.0/24` carece de pasarela predeterminada y de encaminamiento hacia ninguna
otra red. La máquina atacante dispone de un segundo adaptador con salida a internet, empleado
exclusivamente para la instalación de dependencias y en ningún caso para el tráfico de escaneo.

**Conexiones temporales a internet.** Ubuntu Server ha tenido dos conexiones temporales a NAT,
descritas en el apartado 5, ambas con su reversión verificada. Metasploitable 2 no ha tenido
ninguna y no debe tenerla nunca.

**Exposición del anfitrión.** Mantener el adaptador virtual del anfitrión conectado a VMnet2 crea
una ruta entre el equipo del autor y una máquina deliberadamente vulnerable, que expone entre otros
servicios un intérprete de órdenes sin autenticación, un servidor IRC con puerta trasera conocida y
un servicio de escritorio remoto sin cifrar. El riesgo queda contenido por tratarse de un segmento
*host-only* sin encaminamiento, pero debe constar explícitamente. La alternativa, si se prefiere
eliminarlo, es desmarcar la casilla correspondiente en el editor de red virtual, asumiendo la
pérdida de las facilidades de depuración.

Ninguna de las técnicas implementadas se dirige en ningún momento contra sistemas ajenos a este
laboratorio. El marco normativo aplicable comprende los artículos 197 bis y 264 del Código Penal
español, relativos al acceso no autorizado a sistemas de información y a los daños informáticos, y
el Reglamento General de Protección de Datos en lo que resulte de aplicación.
