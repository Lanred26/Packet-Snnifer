#pragma once

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600   // Windows Vista+ : habilita inet_pton, getnameinfo, etc.
#endif

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>

#include <pcap.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <stdbool.h>
#include <conio.h>

// -----------------------------------------------------------------------
#define PROTO_ICMP   1
#define PROTO_TCP    6
#define PROTO_UDP    17

#define ETHERNET_HDR_LEN 14
#define MAX_PACKETS  4096
#define MAX_RAW_SHOW 256
#define MAX_NODES    256          // dispositivos distintos rastreados (Area 4)
#define MAX_HOSTNAME 64

// -----------------------------------------------------------------------
#pragma pack(push, 1)
typedef struct {
    uint8_t  ver_ihl;
    uint8_t  tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t flags_frag;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
} ip_header_t;

typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t  data_offset;
    uint8_t  flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_ptr;
} tcp_header_t;

typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
} udp_header_t;

typedef struct {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    uint16_t id;
    uint16_t seq;
} icmp_header_t;
#pragma pack(pop)

#define TCP_FIN  0x01
#define TCP_SYN  0x02
#define TCP_RST  0x04
#define TCP_PSH  0x08
#define TCP_ACK  0x10
#define TCP_URG  0x20

// -----------------------------------------------------------------------
typedef struct {
    int      index;
    time_t   timestamp;
    char     time_str[32];
    char     src_ip[INET_ADDRSTRLEN];
    char     dst_ip[INET_ADDRSTRLEN];
    int      src_port;
    int      dst_port;
    uint8_t  protocol;
    char     proto_str[8];
    uint16_t total_len;
    uint16_t ip_id;
    uint8_t  ttl;
    uint8_t  tos;
    uint8_t  tcp_flags;
    uint8_t  icmp_type;
    uint8_t  icmp_code;
    uint32_t tcp_seq;
    uint32_t tcp_ack;
    uint8_t  raw[MAX_RAW_SHOW];
    int      raw_len;
} packet_record_t;

// -----------------------------------------------------------------------
typedef struct {
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    int  src_port;
    int  dst_port;
    int  protocol;
    bool active;
  
    bool node_filter_active;
    char node_filter_ip[INET_ADDRSTRLEN];
} filter_t;

// -----------------------------------------------------------------------
// Nodo de red rastreado para Area 4 / Top Talkers
// -----------------------------------------------------------------------
typedef struct {
    char     ip[INET_ADDRSTRLEN];
    char     hostname[MAX_HOSTNAME];   // resuelto via getnameinfo, "" si no resuelto aun
    bool     resolve_attempted;
    bool     resolve_pending;          // resolviendose en hilo aparte
    uint64_t bytes_sent;               // bytes donde este nodo es src
    uint64_t bytes_recv;               // bytes donde este nodo es dst
    uint32_t packets_sent;
    uint32_t packets_recv;
    time_t   last_seen;
} node_info_t;

// -----------------------------------------------------------------------
typedef struct {
    pcap_t          *handle;
    packet_record_t  packets[MAX_PACKETS];
    int              count;
    int              total_seen;
    volatile bool    running;
    volatile bool    want_restart;
    filter_t         filter;
    CRITICAL_SECTION lock;

    // Tabla de nodos / dispositivos (Area 4 + Top Talkers)
    node_info_t      nodes[MAX_NODES];
    int              node_count;
    CRITICAL_SECTION node_lock;
} sniffer_state_t;

// -----------------------------------------------------------------------
DWORD WINAPI capture_thread(LPVOID arg);
void  packet_handler(u_char *param, const struct pcap_pkthdr *header,
                     const u_char *pkt_data);
bool  apply_filter(const packet_record_t *rec, const filter_t *f);

void ui_run(sniffer_state_t *state);
void ui_print_area1(const sniffer_state_t *state, int selected, int scroll_top);
void ui_print_area2(const packet_record_t *rec);
void ui_print_area3(const packet_record_t *rec);
void ui_print_menu(const sniffer_state_t *state);
void ui_clear_screen(void);
void ui_get_console_size(int *cols, int *rows);

bool export_csv(const sniffer_state_t *state, const char *filename);

int  list_devices(pcap_if_t **all_devs, char *errbuf);
int  select_device(pcap_if_t *all_devs);

// nodes.cpp
void node_track(sniffer_state_t *state, const char *ip, uint16_t bytes, bool is_src);
void node_resolve_async(sniffer_state_t *state, const char *ip);
int  node_get_top_talkers(sniffer_state_t *state, node_info_t *out, int max_out);
