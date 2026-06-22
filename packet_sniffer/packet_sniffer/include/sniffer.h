#pragma once

// Windows + Npcap includes - order matters
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>

// Npcap SDK
#include <pcap.h>

// Standard
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <stdbool.h>
#include <conio.h>

// -----------------------------------------------------------------------
// Protocol number constants (mirror IPPROTO_* for portability)
// -----------------------------------------------------------------------
#define PROTO_ICMP   1
#define PROTO_TCP    6
#define PROTO_UDP    17

// -----------------------------------------------------------------------
// Ethernet header length
// -----------------------------------------------------------------------
#define ETHERNET_HDR_LEN 14

// -----------------------------------------------------------------------
// Maximum packets stored in the ring buffer shown in Area 1
// -----------------------------------------------------------------------
#define MAX_PACKETS 4096

// -----------------------------------------------------------------------
// Maximum raw bytes shown in Area 3
// -----------------------------------------------------------------------
#define MAX_RAW_SHOW 256

// -----------------------------------------------------------------------
// IP header (RFC 791)
// -----------------------------------------------------------------------
#pragma pack(push, 1)
typedef struct {
    uint8_t  ver_ihl;       // version (4 bits) + IHL (4 bits)
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

// TCP header (RFC 793)
typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t  data_offset;   // data offset (4 bits) + reserved (4 bits)
    uint8_t  flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_ptr;
} tcp_header_t;

// UDP header (RFC 768)
typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
} udp_header_t;

// ICMP header (RFC 792)
typedef struct {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    uint16_t id;
    uint16_t seq;
} icmp_header_t;
#pragma pack(pop)

// -----------------------------------------------------------------------
// TCP flags
// -----------------------------------------------------------------------
#define TCP_FIN  0x01
#define TCP_SYN  0x02
#define TCP_RST  0x04
#define TCP_PSH  0x08
#define TCP_ACK  0x10
#define TCP_URG  0x20

// -----------------------------------------------------------------------
// Captured packet record stored in the ring buffer
// -----------------------------------------------------------------------
typedef struct {
    int      index;                     // sequential number shown in Area 1
    time_t   timestamp;
    char     time_str[32];
    char     src_ip[INET_ADDRSTRLEN];
    char     dst_ip[INET_ADDRSTRLEN];
    int      src_port;                  // 0 for ICMP
    int      dst_port;                  // 0 for ICMP
    uint8_t  protocol;                  // PROTO_TCP / UDP / ICMP / other
    char     proto_str[8];
    uint16_t total_len;
    uint16_t ip_id;
    uint8_t  ttl;
    uint8_t  tos;
    uint8_t  tcp_flags;                 // only meaningful for TCP
    uint8_t  icmp_type;
    uint8_t  icmp_code;
    uint32_t tcp_seq;
    uint32_t tcp_ack;
    uint8_t  raw[MAX_RAW_SHOW];
    int      raw_len;
} packet_record_t;

// -----------------------------------------------------------------------
// Filter settings (all optional; empty string = no filter for that field)
// -----------------------------------------------------------------------
typedef struct {
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    int  src_port;                      // 0 = any
    int  dst_port;                      // 0 = any
    int  protocol;                      // 0 = any, PROTO_TCP/UDP/ICMP otherwise
    bool active;                        // false = capture everything
} filter_t;

// -----------------------------------------------------------------------
// Global state shared between capture thread and UI
// -----------------------------------------------------------------------
typedef struct {
    pcap_t          *handle;
    packet_record_t  packets[MAX_PACKETS];
    int              count;             // total packets stored (capped at MAX_PACKETS)
    int              total_seen;        // total packets processed (can exceed MAX_PACKETS)
    volatile bool    running;           // capture loop flag
    filter_t         filter;
    CRITICAL_SECTION lock;             // protects packets[], count, total_seen
} sniffer_state_t;

// -----------------------------------------------------------------------
// Function prototypes
// -----------------------------------------------------------------------

// capture.cpp
DWORD WINAPI capture_thread(LPVOID arg);
void  packet_handler(u_char *param, const struct pcap_pkthdr *header,
                     const u_char *pkt_data);
bool  apply_filter(const packet_record_t *rec, const filter_t *f);

// ui.cpp
void ui_run(sniffer_state_t *state);
void ui_print_area1(const sniffer_state_t *state, int selected, int scroll_top);
void ui_print_area2(const packet_record_t *rec);
void ui_print_area3(const packet_record_t *rec);
void ui_print_menu(const sniffer_state_t *state);
void ui_clear_screen(void);
void ui_get_console_size(int *cols, int *rows);

// export.cpp
bool export_csv(const sniffer_state_t *state, const char *filename);

// device.cpp
int  list_devices(pcap_if_t **all_devs, char *errbuf);
int  select_device(pcap_if_t *all_devs);
