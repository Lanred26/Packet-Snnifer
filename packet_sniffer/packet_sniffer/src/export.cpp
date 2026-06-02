/*
 * export.cpp
 * Exports captured packets to a CSV file.
 */

#include "../include/sniffer.h"

bool export_csv(const sniffer_state_t *state, const char *filename)
{
    FILE *fp = fopen(filename, "w");
    if (!fp)
        return false;

    // Header row
    fprintf(fp, "Index,Time,Protocol,Src_IP,Dst_IP,Src_Port,Dst_Port,"
                "Total_Len,IP_ID,TTL,TOS,TCP_Flags,ICMP_Type,ICMP_Code\n");

    EnterCriticalSection((CRITICAL_SECTION *)&state->lock);

    for (int i = 0; i < state->count && i < MAX_PACKETS; i++)
    {
        int slot = i % MAX_PACKETS;
        const packet_record_t *rec = &state->packets[slot];

        // Build TCP flags string
        char flags[8] = "------";
        if (rec->protocol == PROTO_TCP)
        {
            flags[0] = (rec->tcp_flags & TCP_SYN) ? 'S' : '-';
            flags[1] = (rec->tcp_flags & TCP_ACK) ? 'A' : '-';
            flags[2] = (rec->tcp_flags & TCP_FIN) ? 'F' : '-';
            flags[3] = (rec->tcp_flags & TCP_RST) ? 'R' : '-';
            flags[4] = (rec->tcp_flags & TCP_PSH) ? 'P' : '-';
            flags[5] = (rec->tcp_flags & TCP_URG) ? 'U' : '-';
            flags[6] = '\0';
        }

        fprintf(fp, "%d,%s,%s,%s,%s,%d,%d,%d,%d,%d,%d,%s,%d,%d\n",
                rec->index,
                rec->time_str,
                rec->proto_str,
                rec->src_ip,
                rec->dst_ip,
                rec->src_port,
                rec->dst_port,
                rec->total_len,
                rec->ip_id,
                rec->ttl,
                rec->tos,
                flags,
                rec->icmp_type,
                rec->icmp_code);
    }

    LeaveCriticalSection((CRITICAL_SECTION *)&state->lock);
    fclose(fp);
    return true;
}
