# PACKET SNIFFER - Manual del Usuario
## Proyecto Redes I

---

## 1. Descripcion

Packet Sniffer es una herramienta de captura y analisis de trafico de red desarrollada en C++ utilizando la libreria Npcap para Windows. Permite capturar paquetes IPv4 en tiempo real, filtrarlos por multiples criterios y exportar los resultados a CSV.

---

## 2. Requisitos del sistema

| Componente        | Requisito                                      |
|-------------------|------------------------------------------------|
| Sistema operativo | Windows 10 / 11 (64-bit)                       |
| Npcap             | Version 1.70 o superior (https://npcap.com)    |
| Privilegios       | Administrador (requerido por Npcap)            |
| Compilador        | MinGW-w64 g++ con soporte C++11 (para compilar)|
| Npcap SDK         | Incluido en instalador de Npcap                |

---

## 3. Instalacion

### 3.1 Instalar Npcap

1. Descargar desde https://npcap.com/#download
2. Ejecutar el instalador como Administrador
3. Seleccionar la opcion **"Install Npcap in WinPcap API-compatible Mode"** si se va a compilar con el SDK de WinPcap

### 3.2 Compilar el proyecto

Abrir MSYS2 MinGW 64-bit y ejecutar:

```
cd /ruta/al/proyecto
make NPCAP_SDK="C:/Program Files/Npcap/sdk"
```

Si Npcap SDK esta en otra ubicacion, ajustar la variable `NPCAP_SDK`.

### 3.3 Ejecutar

Abrir cmd o PowerShell **como Administrador**:

```
sniffer.exe
```

---

## 4. Interfaz de usuario

La aplicacion utiliza una interfaz de texto dividida en tres areas claramente delimitadas:

```
+---------------------------------------------------------------+
| TITULO / BARRA DE MENU                                        |
+---------------------------------------------------------------+
| AREA 1 - Lista de trafico capturado (scrollable)              |
|  # | Time     | Src IP          | Dst IP         | Proto |... |
+---------------------------------------------------------------+
| AREA 2 - Detalle estructurado del paquete seleccionado        |
|  [IP]  Src: ...  Dst: ...  TTL: ...                          |
|  [TCP] SPort: ...  DPort: ...  Flags: SA----                  |
+---------------------------------------------------------------+
| AREA 3 - Volcado hexadecimal (raw) del paquete seleccionado   |
|  0000  45 00 00 3c ...  E..<                                  |
+---------------------------------------------------------------+
| BARRA DE ESTADO                                               |
+---------------------------------------------------------------+
```

### Colores por protocolo (Area 1)

| Color          | Protocolo |
|----------------|-----------|
| Verde brillante| TCP       |
| Amarillo       | UDP       |
| Rojo brillante | ICMP      |
| Blanco         | Otro      |

---

## 5. Controles de teclado

| Tecla   | Accion                                              |
|---------|-----------------------------------------------------|
| ARRIBA  | Mover seleccion hacia arriba en Area 1              |
| ABAJO   | Mover seleccion hacia abajo en Area 1               |
| S       | Iniciar / Detener captura                           |
| F       | Abrir dialogo de configuracion de filtros           |
| E       | Exportar trafico capturado a archivo CSV            |
| C       | Limpiar buffer de captura                           |
| Q       | Salir del programa                                  |

---

## 6. Filtros de captura

Al presionar **F** se abre el dialogo de filtros. Se pueden configurar los siguientes criterios (dejar en blanco para ignorar ese campo):

| Campo          | Ejemplo           | Descripcion                      |
|----------------|-------------------|----------------------------------|
| IP Fuente      | 192.168.1.10      | Solo paquetes con ese IP origen  |
| IP Destino     | 8.8.8.8           | Solo paquetes con ese IP destino |
| Puerto Fuente  | 80                | Puerto TCP/UDP origen            |
| Puerto Destino | 443               | Puerto TCP/UDP destino           |
| Protocolo      | 6 (TCP), 17 (UDP), 1 (ICMP), 0=cualquiera |

Los filtros se aplican en tiempo real. Los paquetes que no cumplan los criterios no se almacenan en el buffer. Para desactivar todos los filtros, volver al dialogo y dejar todos los campos en blanco.

---

## 7. Exportacion a CSV

Al presionar **E**, el programa solicita un nombre de archivo (por defecto `capture.csv`). El archivo se guarda en el directorio de trabajo actual.

### Columnas del CSV

```
Index, Time, Protocol, Src_IP, Dst_IP, Src_Port, Dst_Port,
Total_Len, IP_ID, TTL, TOS, TCP_Flags, ICMP_Type, ICMP_Code
```

**TCP_Flags** usa la notacion: `S`=SYN, `A`=ACK, `F`=FIN, `R`=RST, `P`=PSH, `U`=URG, `-`=no activo.

---

## 8. Area 2 - Informacion estructurada

Muestra los campos del encabezado del paquete seleccionado en Area 1:

**Para todos los paquetes IP:**
- IP origen y destino
- Identificador IP, TTL, TOS, longitud total

**Para TCP adicionalmente:**
- Puerto origen y destino
- Numero de secuencia y acuse de recibo
- Banderas: SYN, ACK, FIN, RST, PSH, URG

**Para UDP adicionalmente:**
- Puerto origen y destino

**Para ICMP adicionalmente:**
- Tipo y codigo ICMP

---

## 9. Area 3 - Volcado hexadecimal

Muestra los primeros 64 bytes del paquete en formato hex + ASCII, igual que Wireshark. El offset se indica en la columna izquierda.

---

## 10. Limitaciones conocidas

- Solo captura trafico IPv4 sobre interfaces Ethernet (DLT_EN10MB).
- El buffer interno almacena hasta 4096 paquetes; al superarlo se sobreescriben los mas antiguos.
- El volcado raw muestra un maximo de 64 bytes en pantalla (256 bytes se guardan internamente para exportacion futura).
- La funcion Start despues de Stop requiere reiniciar la aplicacion en esta version.

---

## 11. Compilacion manual (alternativa al Makefile)

```
g++ -std=c++11 -o sniffer.exe ^
    src/main.cpp src/capture.cpp src/ui.cpp src/export.cpp src/device.cpp ^
    -I include ^
    -I "C:/Program Files/Npcap/sdk/Include" ^
    -L "C:/Program Files/Npcap/sdk/Lib/x64" ^
    -lwpcap -lws2_32 -lIPHlpApi
```

---

## 12. Referencias

- https://npcap.com/guide/npcap-tutorial.html
- https://www.tcpdump.org/
- https://talalio.medium.com/building-a-packet-sniffer-9460f394041
- https://www.wireshark.org/
