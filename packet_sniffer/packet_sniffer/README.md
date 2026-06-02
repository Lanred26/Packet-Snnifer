# Packet Sniffer - Redes I

Herramienta de captura y analisis de trafico de red en C++ con Npcap (Windows).

## Estructura del proyecto

```
packet_sniffer/
├── include/
│   └── sniffer.h       # Headers, structs, prototipos globales
├── src/
│   ├── main.cpp        # Entrada, seleccion de interfaz, hilo de captura
│   ├── capture.cpp     # Callback de pcap_loop, parseo de headers IP/TCP/UDP/ICMP
│   ├── ui.cpp          # Interfaz de texto: Area1/Area2/Area3, controles
│   ├── export.cpp      # Exportacion CSV
│   └── device.cpp      # Enumeracion y seleccion de interfaces Npcap
├── Makefile
├── MANUAL_USUARIO.md
└── README.md
```

## Compilar

```
make NPCAP_SDK="C:/Program Files/Npcap/sdk"
```

## Ejecutar

Ejecutar `sniffer.exe` como Administrador.

## Funcionalidades implementadas

- Captura en tiempo real de paquetes IPv4
- 3 areas: lista de trafico / detalle estructurado / volcado hex raw
- Filtros por: IP fuente, IP destino, puerto fuente, puerto destino, protocolo (5 filtros)
- Exportacion a CSV
- Soporte TCP (con banderas), UDP, ICMP
- Colores por protocolo
- Seleccion de interfaz de red al inicio
- Inicio/pausa de captura desde la UI
- Limpieza del buffer desde la UI
