/*
 * capture.cpp
 * Packet capture thread using Npcap/WinPcap API.
 * Parses Ethernet -> IP -> TCP/UDP/ICMP headers.
 */

#include "../include/sniffer.h"

// -----------------------------------------------------------------------
// apply_filter: returns true if the record passes the active filter
// -----------------------------------------------------------------------
bool apply_filter(const packet_record_t *rec, const filter_t *f)
{
    if (!f->active)
        return true;

    // Source IP filter
    if (f->src_ip[0] != '\0' && strcmp(f->src_ip, rec->src_ip) != 0)
        return false;

    // Destination IP filter
    if (f->dst_ip[0] != '\0' && strcmp(f->dst_ip, rec->dst_ip) != 0)
        return false;

    // Source port filter (0 = any)
    if (f->src_port != 0 && f->src_port != rec->src_port)
        return false;

    // Destination port filter
    if (f->dst_port != 0 && f->dst_port != rec->dst_port)
        return false;

    // Protocol filter
    if (f->protocol != 0 && f->protocol != rec->protocol)
        return false;

    return true;
}

// -----------------------------------------------------------------------
// ip_to_str: converts a 32-bit network-order IP to dotted-decimal string
// -----------------------------------------------------------------------
static void ip_to_str(uint32_t ip_net, char *buf)
{
    struct in_addr addr;
    addr.s_addr = ip_net;
    strncpy(buf, inet_ntoa(addr), INET_ADDRSTRLEN - 1);
    buf[INET_ADDRSTRLEN - 1] = '\0';
}

// -----------------------------------------------------------------------
// packet_handler: called by pcap_loop for every captured frame
// -----------------------------------------------------------------------
void packet_handler(u_char *param,
                    const struct pcap_pkthdr *header,
                    const u_char *pkt_data)
{
    sniffer_state_t *state = (sniffer_state_t *)param;

    if (!state->running)
    {
        pcap_breakloop(state->handle);
        return;
    }

    // Need at least Ethernet + IP header
    if (header->caplen < (ETHERNET_HDR_LEN + sizeof(ip_header_t)))
        return;

    // Skip Ethernet header
    const u_char *ip_ptr = pkt_data + ETHERNET_HDR_LEN;

    // Check EtherType = IPv4 (0x0800)
    uint16_t ethertype = ntohs(*(uint16_t *)(pkt_data + 12));
    if (ethertype != 0x0800)
        return;

    const ip_header_t *ip = (const ip_header_t *)ip_ptr;
    int ip_hdr_len = (ip->ver_ihl & 0x0F) * 4;

    if (ip_hdr_len < 20)
        return;

    // Build record
    packet_record_t rec;
    memset(&rec, 0, sizeof(rec));

    rec.timestamp  = time(NULL);
    rec.ip_id      = ntohs(ip->id);
    rec.ttl        = ip->ttl;
    rec.tos        = ip->tos;
    rec.total_len  = ntohs(ip->total_len);
    rec.protocol   = ip->protocol;

    ip_to_str(ip->src_ip, rec.src_ip);
    ip_to_str(ip->dst_ip, rec.dst_ip);

    // Format timestamp
    struct tm *tm_info = localtime(&rec.timestamp);
    strftime(rec.time_str, sizeof(rec.time_str), "%H:%M:%S", tm_info);

    // Parse transport layer
    const u_char *transport_ptr = ip_ptr + ip_hdr_len;
    int remaining = (int)header->caplen - ETHERNET_HDR_LEN - ip_hdr_len;

    switch (ip->protocol)
    {
        case PROTO_TCP:
            strncpy(rec.proto_str, "TCP", sizeof(rec.proto_str) - 1);
            if (remaining >= (int)sizeof(tcp_header_t))
            {
                const tcp_header_t *tcp = (const tcp_header_t *)transport_ptr;
                rec.src_port  = ntohs(tcp->src_port);
                rec.dst_port  = ntohs(tcp->dst_port);
                rec.tcp_flags = tcp->flags;
                rec.tcp_seq   = ntohl(tcp->seq);
                rec.tcp_ack   = ntohl(tcp->ack);
            }
            break;

        case PROTO_UDP:
            strncpy(rec.proto_str, "UDP", sizeof(rec.proto_str) - 1);
            if (remaining >= (int)sizeof(udp_header_t))
            {
                const udp_header_t *udp = (const udp_header_t *)transport_ptr;
                rec.src_port = ntohs(udp->src_port);
                rec.dst_port = ntohs(udp->dst_port);
            }
            break;

        case PROTO_ICMP:
            strncpy(rec.proto_str, "ICMP", sizeof(rec.proto_str) - 1);
            if (remaining >= (int)sizeof(icmp_header_t))
            {
                const icmp_header_t *icmp = (const icmp_header_t *)transport_ptr;
                rec.icmp_type = icmp->type;
                rec.icmp_code = icmp->code;
            }
            break;

        default:
            snprintf(rec.proto_str, sizeof(rec.proto_str), "%d", ip->protocol);
            break;
    }

    // Apply user filter
    EnterCriticalSection(&state->lock);
    state->total_seen++;

    if (apply_filter(&rec, &state->filter))
    {
        // Raw bytes (capped at MAX_RAW_SHOW)
        rec.raw_len = (int)header->caplen > MAX_RAW_SHOW
                      ? MAX_RAW_SHOW
                      : (int)header->caplen;
        memcpy(rec.raw, pkt_data, rec.raw_len);

        int slot = state->count % MAX_PACKETS;
        rec.index = state->count + 1;
        state->packets[slot] = rec;
        state->count++;
    }
    LeaveCriticalSection(&state->lock);
}

// -----------------------------------------------------------------------
// capture_thread: entry point for the background capture thread
// -----------------------------------------------------------------------
DWORD WINAPI capture_thread(LPVOID arg)
{
    sniffer_state_t *state = (sniffer_state_t *)arg;
    // pcap_loop returns when pcap_breakloop is called or on error
    pcap_loop(state->handle, 0, packet_handler, (u_char *)state);
    return 0;
}
