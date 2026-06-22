/*
 * nodes.cpp
 * Rastreo de dispositivos/nodos de red para:
 *   - Area 4 (lista de dispositivos con nombre resuelto)
 *   - Panel de estadisticas Top Talkers (tecla T)
 *
 * Resolucion de nombre en dos pasos:
 *   1. Si la IP es de LAN local (RFC1918), intenta NetBIOS Name Query
 *      (UDP 137) primero, porque routers/PCs Windows en LAN casi
 *      siempre responden a esto aunque no tengan PTR en DNS.
 *   2. Si NetBIOS no responde o la IP no es LAN, intenta DNS inverso
 *      via gethostbyaddr (funciona bien para dominios publicos:
 *      Akamai, Google, GitHub, etc.)
 *
 * Todo ocurre en un hilo separado por IP, fire-and-forget, para no
 * bloquear la captura ni la UI. resolve_attempted/resolve_pending
 * garantizan un solo intento por IP en toda la ejecucion.
 */

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif

#include "../include/sniffer.h"

// -----------------------------------------------------------------------
// Busca un nodo existente por IP, o crea uno nuevo si hay espacio.
// Debe llamarse con node_lock ya tomado.
// -----------------------------------------------------------------------
static node_info_t *find_or_create_node(sniffer_state_t *state, const char *ip)
{
    for (int i = 0; i < state->node_count; i++)
        if (strcmp(state->nodes[i].ip, ip) == 0)
            return &state->nodes[i];

    if (state->node_count >= MAX_NODES)
        return NULL;

    node_info_t *n = &state->nodes[state->node_count++];
    memset(n, 0, sizeof(*n));
    strncpy(n->ip, ip, INET_ADDRSTRLEN - 1);
    n->hostname[0] = '\0';
    return n;
}

void node_track(sniffer_state_t *state, const char *ip, uint16_t bytes, bool is_src)
{
    EnterCriticalSection(&state->node_lock);
    node_info_t *n = find_or_create_node(state, ip);
    if (n)
    {
        n->last_seen = time(NULL);
        if (is_src) { n->bytes_sent += bytes; n->packets_sent++; }
        else        { n->bytes_recv += bytes; n->packets_recv++; }
    }
    LeaveCriticalSection(&state->node_lock);
}

// -----------------------------------------------------------------------
// Detecta si una IPv4 (en host order) pertenece a un rango RFC1918
// (LAN privada): 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
// -----------------------------------------------------------------------
static bool is_private_lan(uint32_t ip_host_order)
{
    uint8_t b0 = (ip_host_order >> 24) & 0xFF;
    uint8_t b1 = (ip_host_order >> 16) & 0xFF;

    if (b0 == 10) return true;
    if (b0 == 172 && b1 >= 16 && b1 <= 31) return true;
    if (b0 == 192 && b1 == 168) return true;
    return false;
}

// -----------------------------------------------------------------------
// NetBIOS Name Query (UDP/137) - consulta directa al estilo "nbtstat -A"
// sin usar la API NCB (que requiere el driver NetBT cargado de forma
// especial); se arma el paquete UDP a mano, mas portable entre
// versiones de MinGW.
//
// Devuelve true si obtuvo un nombre, lo copia en out_name.
// -----------------------------------------------------------------------
static bool netbios_query(const char *ip, char *out_name, size_t out_len)
{
    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) return false;

    // Timeout corto: 600ms. LAN local responde casi instantaneo si
    // el host existe y tiene NetBIOS habilitado; si no, no vale la
    // pena esperar mas porque bloqueamos un hilo dedicado de todos
    // modos (no la UI ni la captura).
    DWORD timeout = 600;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout));

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port   = htons(137);
    dest.sin_addr.s_addr = inet_addr(ip);

    // Paquete NBSTAT query estandar (NBTSTAT -A equivalente)
    unsigned char query[50] = {
        0xA2, 0x41,             // Transaction ID
        0x00, 0x00,             // Flags (consulta estandar, no recursiva)
        0x00, 0x01,             // Questions: 1
        0x00, 0x00,             // Answer RRs: 0
        0x00, 0x00,             // Authority RRs: 0
        0x00, 0x00,             // Additional RRs: 0
        // Nombre NetBIOS codificado: "*" + padding = wildcard query
        0x20,
        0x43, 0x4B, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x00,
        0x00, 0x21,             // Type: NBSTAT
        0x00, 0x01              // Class: IN
    };

    int sent = sendto(sock, (const char *)query, sizeof(query), 0,
                       (struct sockaddr *)&dest, sizeof(dest));
    if (sent == SOCKET_ERROR) { closesocket(sock); return false; }

    unsigned char resp[1024];
    struct sockaddr_in from;
    int fromlen = sizeof(from);
    int n = recvfrom(sock, (char *)resp, sizeof(resp), 0,
                      (struct sockaddr *)&from, &fromlen);
    closesocket(sock);

    if (n < 57) return false; // respuesta minima invalida o timeout

    // Estructura de respuesta NBSTAT:
    // header(12) + name(34) + type/class(4) + ttl(4) + rdlength(2)
    // + num_names(1) + [16 bytes name + 2 bytes flags] por cada nombre
    int num_names = resp[56];
    if (num_names < 1) return false;

    // El primer nombre suele ser el nombre de maquina (<00> = Workstation)
    int offset = 57;
    if (offset + 16 > n) return false;

    char raw_name[16];
    memcpy(raw_name, resp + offset, 15);
    raw_name[15] = '\0';

    // Recortar espacios finales (NetBIOS rellena con 0x20)
    for (int i = 14; i >= 0; i--)
    {
        if (raw_name[i] == ' ' || raw_name[i] == '\0')
            raw_name[i] = '\0';
        else
            break;
    }

    if (raw_name[0] == '\0') return false;

    strncpy(out_name, raw_name, out_len - 1);
    out_name[out_len - 1] = '\0';
    return true;
}

// -----------------------------------------------------------------------
// Hilo de resolucion: NetBIOS (si LAN) -> DNS inverso (fallback)
// -----------------------------------------------------------------------
typedef struct {
    sniffer_state_t *state;
    char              ip[INET_ADDRSTRLEN];
} resolve_args_t;

static DWORD WINAPI resolve_thread_proc(LPVOID arg)
{
    resolve_args_t *ra = (resolve_args_t *)arg;
    char host[MAX_HOSTNAME];
    host[0] = '\0';
    bool resolved = false;

    uint32_t ip_h = ntohl(inet_addr(ra->ip));

    // Paso 1: NetBIOS si es LAN local
    if (is_private_lan(ip_h))
    {
        char nb_name[MAX_HOSTNAME];
        if (netbios_query(ra->ip, nb_name, sizeof(nb_name)))
        {
            strncpy(host, nb_name, sizeof(host) - 1);
            resolved = true;
        }
    }

    // Paso 2: DNS inverso si NetBIOS no resolvio
    if (!resolved)
    {
        struct sockaddr_in sa;
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_addr.s_addr = inet_addr(ra->ip);

        struct hostent *he = gethostbyaddr((const char *)&sa.sin_addr, sizeof(sa.sin_addr), AF_INET);
        if (he != NULL && he->h_name != NULL && he->h_name[0] != '\0' &&
            strcmp(he->h_name, ra->ip) != 0)
        {
            strncpy(host, he->h_name, sizeof(host) - 1);
            resolved = true;
        }
    }

    EnterCriticalSection(&ra->state->node_lock);
    for (int i = 0; i < ra->state->node_count; i++)
    {
        if (strcmp(ra->state->nodes[i].ip, ra->ip) == 0)
        {
            if (resolved)
                strncpy(ra->state->nodes[i].hostname, host, MAX_HOSTNAME - 1);
            else
                ra->state->nodes[i].hostname[0] = '\0';

            ra->state->nodes[i].resolve_pending = false;
            break;
        }
    }
    LeaveCriticalSection(&ra->state->node_lock);

    free(ra);
    return 0;
}

void node_resolve_async(sniffer_state_t *state, const char *ip)
{
    EnterCriticalSection(&state->node_lock);
    node_info_t *n = find_or_create_node(state, ip);
    bool need_resolve = (n && !n->resolve_attempted && !n->resolve_pending);
    if (need_resolve)
    {
        n->resolve_attempted = true;
        n->resolve_pending   = true;
    }
    LeaveCriticalSection(&state->node_lock);

    if (!need_resolve) return;

    resolve_args_t *ra = (resolve_args_t *)malloc(sizeof(resolve_args_t));
    ra->state = state;
    strncpy(ra->ip, ip, INET_ADDRSTRLEN - 1);
    ra->ip[INET_ADDRSTRLEN - 1] = '\0';

    HANDLE h = CreateThread(NULL, 0, resolve_thread_proc, ra, 0, NULL);
    if (h) CloseHandle(h);
}

// -----------------------------------------------------------------------
static int cmp_total_bytes(const void *a, const void *b)
{
    const node_info_t *na = (const node_info_t *)a;
    const node_info_t *nb = (const node_info_t *)b;
    uint64_t ta = na->bytes_sent + na->bytes_recv;
    uint64_t tb = nb->bytes_sent + nb->bytes_recv;
    if (ta > tb) return -1;
    if (ta < tb) return 1;
    return 0;
}

int node_get_top_talkers(sniffer_state_t *state, node_info_t *out, int max_out)
{
    EnterCriticalSection(&state->node_lock);
    int n = state->node_count;
    if (n > MAX_NODES) n = MAX_NODES;

    static node_info_t tmp[MAX_NODES];
    memcpy(tmp, state->nodes, sizeof(node_info_t) * n);
    LeaveCriticalSection(&state->node_lock);

    qsort(tmp, n, sizeof(node_info_t), cmp_total_bytes);

    int copy_n = (n < max_out) ? n : max_out;
    memcpy(out, tmp, sizeof(node_info_t) * copy_n);
    return copy_n;
}