/*
 * ui.cpp - v3
 * Correcciones:
 *  - Sin parpadeo: solo se redibujan las filas que cambiaron
 *  - Clear reanuda captura + auto-scroll inmediatamente
 *  - Start y regreso de F/E/C siempre reanudan auto-scroll
 *  - wVirtualKeyCode para compatibilidad con MinGW antiguo
 */

#include "../include/sniffer.h"
#include <string.h>
#include <ctype.h>

// -----------------------------------------------------------------------
// Layout
// -----------------------------------------------------------------------
#define ROW_TITLE       0
#define ROW_MENU        1
#define ROW_SEP1        2
#define ROW_AREA1_LABEL 3
#define ROW_AREA1_HDR   4
#define ROW_AREA1_START 5
#define AREA1_ROWS      10
#define ROW_SEP2        (ROW_AREA1_START + AREA1_ROWS)
#define ROW_AREA2_LABEL (ROW_SEP2 + 1)
#define ROW_AREA2_IP    (ROW_AREA2_LABEL + 1)
#define ROW_AREA2_PROTO (ROW_AREA2_IP + 1)
#define ROW_AREA2_PAD   (ROW_AREA2_PROTO + 1)
#define ROW_SEP3        (ROW_AREA2_PAD + 1)
#define ROW_AREA3_LABEL (ROW_SEP3 + 1)
#define ROW_AREA3_HDR   (ROW_AREA3_LABEL + 1)
#define ROW_AREA3_START (ROW_AREA3_HDR + 1)
#define AREA3_HEX_ROWS  4
#define ROW_SEP4        (ROW_AREA3_START + AREA3_HEX_ROWS)

// Botones del menu
#define BTN_S_X   2
#define BTN_S_LEN 12
#define BTN_F_X   16
#define BTN_F_LEN 8
#define BTN_E_X   26
#define BTN_E_LEN 12
#define BTN_C_X   40
#define BTN_C_LEN 7
#define BTN_Q_X   49
#define BTN_Q_LEN 6

// -----------------------------------------------------------------------
// Helpers de consola
// -----------------------------------------------------------------------
void ui_clear_screen(void)
{
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    COORD c = {0, 0};
    DWORD written;
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    GetConsoleScreenBufferInfo(h, &csbi);
    DWORD size = csbi.dwSize.X * csbi.dwSize.Y;
    FillConsoleOutputCharacter(h, ' ', size, c, &written);
    FillConsoleOutputAttribute(h, csbi.wAttributes, size, c, &written);
    SetConsoleCursorPosition(h, c);
}

static void gotoxy(int x, int y)
{
    COORD coord = {(SHORT)x, (SHORT)y};
    SetConsoleCursorPosition(GetStdHandle(STD_OUTPUT_HANDLE), coord);
}

static void set_color(WORD attr)
{
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), attr);
}

void ui_get_console_size(int *cols, int *rows)
{
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi);
    *cols = csbi.srWindow.Right  - csbi.srWindow.Left + 1;
    *rows = csbi.srWindow.Bottom - csbi.srWindow.Top  + 1;
}

static void hide_cursor(void)
{
    CONSOLE_CURSOR_INFO ci = {1, FALSE};
    SetConsoleCursorInfo(GetStdHandle(STD_OUTPUT_HANDLE), &ci);
}

// Escribe una fila entera rellenando hasta 'cols' con espacios (sin \n)
static void write_padded(int row, int cols, const char *buf, WORD color)
{
    gotoxy(0, row);
    set_color(color);
    int len = (int)strlen(buf);
    fputs(buf, stdout);
    for (int i = len; i < cols; i++) putchar(' ');
}

static void hline(int row, int cols)
{
    gotoxy(0, row);
    set_color(FOREGROUND_GREEN);
    for (int i = 0; i < cols; i++) putchar('-');
}

// -----------------------------------------------------------------------
// Mouse
// -----------------------------------------------------------------------
static HANDLE g_hStdin = INVALID_HANDLE_VALUE;

static void mouse_enable(void)
{
    g_hStdin = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode;
    GetConsoleMode(g_hStdin, &mode);
    mode &= ~ENABLE_QUICK_EDIT_MODE;
    mode |= ENABLE_MOUSE_INPUT | ENABLE_EXTENDED_FLAGS;
    SetConsoleMode(g_hStdin, mode);
}

static void mouse_disable(void)
{
    if (g_hStdin == INVALID_HANDLE_VALUE) return;
    DWORD mode;
    GetConsoleMode(g_hStdin, &mode);
    mode &= ~ENABLE_MOUSE_INPUT;
    mode |= ENABLE_QUICK_EDIT_MODE;
    SetConsoleMode(g_hStdin, mode);
}

static char hit_menu_button(int cx, int cy)
{
    if (cy != ROW_MENU) return 0;
    if (cx >= BTN_S_X && cx < BTN_S_X + BTN_S_LEN) return 'S';
    if (cx >= BTN_F_X && cx < BTN_F_X + BTN_F_LEN) return 'F';
    if (cx >= BTN_E_X && cx < BTN_E_X + BTN_E_LEN) return 'E';
    if (cx >= BTN_C_X && cx < BTN_C_X + BTN_C_LEN) return 'C';
    if (cx >= BTN_Q_X && cx < BTN_Q_X + BTN_Q_LEN) return 'Q';
    return 0;
}

// -----------------------------------------------------------------------
// Dibujo del marco fijo (solo se llama una vez al inicio y al volver
// de pantallas secundarias)
// -----------------------------------------------------------------------
static void draw_static_frame(int cols)
{
    hline(ROW_SEP1, cols);
    write_padded(ROW_AREA1_LABEL, cols,
        "  AREA 1 - Captured Traffic  [click para seleccionar | rueda para scroll]",
        FOREGROUND_GREEN | FOREGROUND_INTENSITY);

    // Header columnas Area 1
    gotoxy(0, ROW_AREA1_HDR);
    set_color(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    printf("  %-5s %-10s %-16s %-16s %-6s %-6s %-7s %-7s",
           "#","Time","Src IP","Dst IP","SPort","DPort","Proto","Len");

    hline(ROW_SEP2, cols);
    write_padded(ROW_AREA2_LABEL, cols,
        "  AREA 2 - Packet Detail",
        FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    hline(ROW_SEP3, cols);
    write_padded(ROW_AREA3_LABEL, cols,
        "  AREA 3 - Raw Hex Dump",
        FOREGROUND_GREEN | FOREGROUND_INTENSITY);

    // Header hex Area 3
    gotoxy(0, ROW_AREA3_HDR);
    set_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    printf("  Offset   00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F   ASCII");

    hline(ROW_SEP4, cols);
    set_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
}

// -----------------------------------------------------------------------
// Titulo
// -----------------------------------------------------------------------
static void draw_title(int cols)
{
    char buf[256];
    snprintf(buf, sizeof(buf), "  PACKET SNIFFER  -  Redes I  -  Npcap");
    write_padded(ROW_TITLE, cols, buf,
        BACKGROUND_BLUE | FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
}

// -----------------------------------------------------------------------
// Menu (se redibuja cada frame porque cambia estado/contador)
// -----------------------------------------------------------------------
static void draw_menu(const sniffer_state_t *state, int cols, bool auto_scroll)
{
    gotoxy(0, ROW_MENU);
    set_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    for (int i = 0; i < cols; i++) putchar(' ');

    struct { int x; const char *label; WORD color; } btns[] = {
        { BTN_S_X, "[S]tart/Stop", FOREGROUND_GREEN | FOREGROUND_INTENSITY },
        { BTN_F_X, "[F]ilter",     FOREGROUND_GREEN | FOREGROUND_INTENSITY },
        { BTN_E_X, "[E]xport CSV", FOREGROUND_GREEN | FOREGROUND_INTENSITY },
        { BTN_C_X, "[C]lear",      FOREGROUND_GREEN | FOREGROUND_INTENSITY },
        { BTN_Q_X, "[Q]uit",       FOREGROUND_RED   | FOREGROUND_INTENSITY },
    };
    for (int i = 0; i < 5; i++) {
        gotoxy(btns[i].x, ROW_MENU);
        set_color(btns[i].color);
        printf("%s", btns[i].label);
    }

    // Estado
    gotoxy(57, ROW_MENU);
    if (state->running) {
        set_color(BACKGROUND_GREEN | FOREGROUND_BLUE);
        printf(" CAPTURING ");
    } else {
        set_color(BACKGROUND_RED | FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
        printf("  STOPPED  ");
    }

    // Contador
    set_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    gotoxy(69, ROW_MENU);
    printf("Pkts:%d/%d    ", state->count, state->total_seen);

    // Auto-scroll indicator
    gotoxy(cols - 22, ROW_MENU);
    if (auto_scroll) {
        set_color(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        printf("[AUTO-SCROLL ON] ");
    } else {
        set_color(FOREGROUND_RED | FOREGROUND_INTENSITY);
        printf("[FIJO - A=reanudar]");
    }

    if (state->filter.active) {
        gotoxy(cols - 44, ROW_MENU);
        set_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        printf("[FILTER ON]");
    }

    set_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
}

// -----------------------------------------------------------------------
// Area 1: solo redibuja filas que cambiaron respecto al frame anterior
// -----------------------------------------------------------------------

// Cache de lo que se mostro en el frame anterior para evitar redibujos
static char  prev_line[AREA1_ROWS][128];
static WORD  prev_color[AREA1_ROWS];
static bool  area1_initialized = false;

static void draw_area1(const sniffer_state_t *state, int selected, int scroll_top, int cols)
{
    if (!area1_initialized) {
        memset(prev_line, 0, sizeof(prev_line));
        memset(prev_color, 0, sizeof(prev_color));
        area1_initialized = true;
    }

    EnterCriticalSection((CRITICAL_SECTION *)&state->lock);
    int total = state->count;

    for (int i = 0; i < AREA1_ROWS; i++)
    {
        int idx = scroll_top + i;
        char linebuf[128];
        WORD color;

        if (idx >= total) {
            linebuf[0] = '\0';
            color = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
        } else {
            int slot = idx % MAX_PACKETS;
            const packet_record_t *rec = &state->packets[slot];

            snprintf(linebuf, sizeof(linebuf),
                "  %-5d %-10s %-16s %-16s %-6d %-6d %-7s %-7d",
                rec->index, rec->time_str,
                rec->src_ip, rec->dst_ip,
                rec->src_port, rec->dst_port,
                rec->proto_str, rec->total_len);

            if (idx == selected)
                color = BACKGROUND_BLUE | FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY;
            else if (rec->protocol == PROTO_TCP)
                color = FOREGROUND_GREEN | FOREGROUND_INTENSITY;
            else if (rec->protocol == PROTO_UDP)
                color = FOREGROUND_RED | FOREGROUND_GREEN;
            else if (rec->protocol == PROTO_ICMP)
                color = FOREGROUND_RED | FOREGROUND_INTENSITY;
            else
                color = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
        }

        // Solo redibujar si cambio
        if (strcmp(prev_line[i], linebuf) != 0 || prev_color[i] != color)
        {
            gotoxy(0, ROW_AREA1_START + i);
            set_color(color);
            int len = (int)strlen(linebuf);
            fputs(linebuf, stdout);
            for (int j = len; j < cols; j++) putchar(' ');

            strncpy(prev_line[i], linebuf, 127);
            prev_line[i][127] = '\0';
            prev_color[i] = color;
        }
    }
    LeaveCriticalSection((CRITICAL_SECTION *)&state->lock);
    set_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
}

static void invalidate_area1_cache(void)
{
    memset(prev_line, 0, sizeof(prev_line));
    memset(prev_color, 0, sizeof(prev_color));
}

// -----------------------------------------------------------------------
// Area 2
// -----------------------------------------------------------------------
static void draw_area2(const packet_record_t *rec, int cols)
{
    // Fila IP
    {
        char buf[256];
        if (!rec)
            snprintf(buf, sizeof(buf), "  (ningún paquete seleccionado)");
        else
            snprintf(buf, sizeof(buf),
                "  [IP]  Src: %-16s  Dst: %-16s  ID: %-6d  TTL: %-4d  TOS: 0x%02X  Len: %d",
                rec->src_ip, rec->dst_ip, rec->ip_id, rec->ttl, rec->tos, rec->total_len);
        write_padded(ROW_AREA2_IP, cols, buf, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    }

    // Fila protocolo
    {
        char buf[256];
        buf[0] = '\0';
        if (rec) {
            if (rec->protocol == PROTO_TCP)
                snprintf(buf, sizeof(buf),
                    "  [TCP] SPort: %-6d  DPort: %-6d  Seq: %-12u  Ack: %-12u  Flags: %c%c%c%c%c%c",
                    rec->src_port, rec->dst_port, rec->tcp_seq, rec->tcp_ack,
                    (rec->tcp_flags & TCP_SYN) ? 'S' : '-',
                    (rec->tcp_flags & TCP_ACK) ? 'A' : '-',
                    (rec->tcp_flags & TCP_FIN) ? 'F' : '-',
                    (rec->tcp_flags & TCP_RST) ? 'R' : '-',
                    (rec->tcp_flags & TCP_PSH) ? 'P' : '-',
                    (rec->tcp_flags & TCP_URG) ? 'U' : '-');
            else if (rec->protocol == PROTO_UDP)
                snprintf(buf, sizeof(buf),
                    "  [UDP] SPort: %-6d  DPort: %-6d",
                    rec->src_port, rec->dst_port);
            else if (rec->protocol == PROTO_ICMP)
                snprintf(buf, sizeof(buf),
                    "  [ICMP] Type: %-4d  Code: %-4d",
                    rec->icmp_type, rec->icmp_code);
            else
                snprintf(buf, sizeof(buf), "  [PROTO %d]", rec->protocol);
        }
        write_padded(ROW_AREA2_PROTO, cols, buf, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    }

    // Padding
    write_padded(ROW_AREA2_PAD, cols, "", FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
}

// -----------------------------------------------------------------------
// Area 3
// -----------------------------------------------------------------------
static void draw_area3(const packet_record_t *rec, int cols)
{
    for (int r = 0; r < AREA3_HEX_ROWS; r++)
    {
        char buf[128];
        buf[0] = '\0';

        if (rec && rec->raw_len > 0)
        {
            int i = r * 16;
            int bytes_to_show = rec->raw_len > (AREA3_HEX_ROWS * 16)
                                ? (AREA3_HEX_ROWS * 16) : rec->raw_len;
            if (i < bytes_to_show)
            {
                char hex[64] = "";
                char asc[20] = "";
                int hpos = 0, apos = 0;
                for (int j = 0; j < 16; j++)
                {
                    if (i + j < bytes_to_show) {
                        hpos += snprintf(hex + hpos, sizeof(hex) - hpos,
                                         "%02X ", rec->raw[i + j]);
                        unsigned char c = rec->raw[i + j];
                        asc[apos++] = (c >= 32 && c < 127) ? c : '.';
                    } else {
                        hpos += snprintf(hex + hpos, sizeof(hex) - hpos, "   ");
                    }
                    if (j == 7) { hex[hpos++] = ' '; hex[hpos] = '\0'; }
                }
                asc[apos] = '\0';
                snprintf(buf, sizeof(buf), "  %04X     %s  %s", i, hex, asc);
            }
        }
        write_padded(ROW_AREA3_START + r, cols, buf,
                     FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    }
}

// -----------------------------------------------------------------------
// Stub para cumplir prototipo en sniffer.h
// -----------------------------------------------------------------------
void ui_print_area1(const sniffer_state_t *s, int sel, int top)
{
    int cols, rows; ui_get_console_size(&cols, &rows);
    draw_area1(s, sel, top, cols);
}
void ui_print_area2(const packet_record_t *rec)
{
    int cols, rows; ui_get_console_size(&cols, &rows);
    draw_area2(rec, cols);
}
void ui_print_area3(const packet_record_t *rec)
{
    int cols, rows; ui_get_console_size(&cols, &rows);
    draw_area3(rec, cols);
}
void ui_print_menu(const sniffer_state_t *state)
{
    int cols, rows; ui_get_console_size(&cols, &rows);
    draw_menu(state, cols, true);
}

// -----------------------------------------------------------------------
// Filter dialog
// -----------------------------------------------------------------------
static void ui_setup_filter(sniffer_state_t *state)
{
    mouse_disable();
    ui_clear_screen();
    set_color(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    printf("\n  === FILTER SETUP ===\n");
    set_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    printf("  Dejar en blanco para ignorar ese campo.\n\n");

    filter_t f;
    memset(&f, 0, sizeof(f));

    printf("  Source IP      : "); fflush(stdout);
    fgets(f.src_ip, sizeof(f.src_ip), stdin);
    f.src_ip[strcspn(f.src_ip, "\r\n")] = '\0';

    printf("  Destination IP : "); fflush(stdout);
    fgets(f.dst_ip, sizeof(f.dst_ip), stdin);
    f.dst_ip[strcspn(f.dst_ip, "\r\n")] = '\0';

    char buf[32];
    printf("  Source Port    : "); fflush(stdout);
    fgets(buf, sizeof(buf), stdin); f.src_port = atoi(buf);

    printf("  Dest Port      : "); fflush(stdout);
    fgets(buf, sizeof(buf), stdin); f.dst_port = atoi(buf);

    printf("  Protocol (0=any, 1=ICMP, 6=TCP, 17=UDP): "); fflush(stdout);
    fgets(buf, sizeof(buf), stdin); f.protocol = atoi(buf);

    f.active = (f.src_ip[0] != '\0' || f.dst_ip[0] != '\0' ||
                f.src_port  != 0    || f.dst_port  != 0     ||
                f.protocol  != 0);

    EnterCriticalSection(&state->lock);
    state->filter = f;
    LeaveCriticalSection(&state->lock);
}

// -----------------------------------------------------------------------
// Export dialog
// -----------------------------------------------------------------------
static void ui_do_export(sniffer_state_t *state)
{
    mouse_disable();
    ui_clear_screen();
    set_color(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    printf("\n  Export to CSV\n");
    set_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    printf("  Filename [capture.csv]: "); fflush(stdout);
    char fname[256] = "capture.csv";
    fgets(fname, sizeof(fname), stdin);
    fname[strcspn(fname, "\r\n")] = '\0';
    if (fname[0] == '\0') strcpy(fname, "capture.csv");

    extern bool export_csv(const sniffer_state_t *, const char *);
    if (export_csv(state, fname)) {
        set_color(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        printf("  Exportado a %s\n", fname);
    } else {
        set_color(FOREGROUND_RED | FOREGROUND_INTENSITY);
        printf("  Export FAILED.\n");
    }
    set_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    printf("  Presiona cualquier tecla...\n");
    _getch();
}

// -----------------------------------------------------------------------
// Restaurar frame completo al volver de pantallas secundarias
// -----------------------------------------------------------------------
static void restore_main_frame(int cols)
{
    ui_clear_screen();
    invalidate_area1_cache();
    draw_static_frame(cols);
    mouse_enable();
}

// -----------------------------------------------------------------------
// Main UI loop
// -----------------------------------------------------------------------
void ui_run(sniffer_state_t *state)
{
    hide_cursor();
    mouse_enable();

    int cols, rows;
    ui_get_console_size(&cols, &rows);

    ui_clear_screen();
    draw_static_frame(cols);

    int  selected    = 0;
    int  scroll_top  = 0;
    bool auto_scroll = true;

    // Cache para detectar cambios y evitar redibujos innecesarios
    int  prev_selected   = -1;
    int  prev_scroll_top = -1;
    int  prev_count      = -1;
    bool prev_running    = !state->running;
    bool prev_auto       = !auto_scroll;

    while (true)
    {
        // ----------------------------------------------------------------
        // Actualizar logica de auto-scroll
        // ----------------------------------------------------------------
        EnterCriticalSection(&state->lock);
        int total = state->count;
        if (auto_scroll && total > 0) {
            selected = total - 1;
            int new_top = selected - AREA1_ROWS + 1;
            if (new_top < 0) new_top = 0;
            scroll_top = new_top;
        }
        packet_record_t sel_rec;
        bool has_sel = (total > 0 && selected >= 0 && selected < total);
        if (has_sel)
            sel_rec = state->packets[selected % MAX_PACKETS];
        LeaveCriticalSection(&state->lock);

        // ----------------------------------------------------------------
        // Redibujar solo lo que cambio (anti-parpadeo)
        // ----------------------------------------------------------------
        bool menu_dirty = (state->running != prev_running ||
                           auto_scroll    != prev_auto    ||
                           total          != prev_count   ||
                           state->filter.active != (prev_count >= 0 && state->filter.active));

        if (menu_dirty) {
            draw_title(cols);
            draw_menu(state, cols, auto_scroll);
            prev_running = state->running;
            prev_auto    = auto_scroll;
            prev_count   = total;
        }

        // Area 1: redibuja solo filas distintas (la funcion hace el diff)
        draw_area1(state, selected, scroll_top, cols);

        // Area 2 y 3: solo si cambio la seleccion
        if (selected != prev_selected || scroll_top != prev_scroll_top) {
            draw_area2(has_sel ? &sel_rec : NULL, cols);
            draw_area3(has_sel ? &sel_rec : NULL, cols);

            // Actualizar label Area 2 con numero de paquete
            gotoxy(0, ROW_AREA2_LABEL);
            set_color(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
            char lbuf[128];
            snprintf(lbuf, sizeof(lbuf),
                "  AREA 2 - Packet Detail  (paquete #%d)%s",
                has_sel ? sel_rec.index : 0,
                "                          ");
            fputs(lbuf, stdout);

            prev_selected   = selected;
            prev_scroll_top = scroll_top;
        }

        // ----------------------------------------------------------------
        // Leer eventos (no bloqueante)
        // ----------------------------------------------------------------
        DWORD nevents = 0;
        GetNumberOfConsoleInputEvents(g_hStdin, &nevents);

        for (DWORD e = 0; e < nevents; e++)
        {
            INPUT_RECORD ir;
            DWORD read;
            ReadConsoleInput(g_hStdin, &ir, 1, &read);

            // ---- MOUSE ----
            if (ir.EventType == MOUSE_EVENT)
            {
                MOUSE_EVENT_RECORD &me = ir.Event.MouseEvent;
                int cx = me.dwMousePosition.X;
                int cy = me.dwMousePosition.Y;

                // Click izquierdo
                if (me.dwButtonState & FROM_LEFT_1ST_BUTTON_PRESSED)
                {
                    // Click en Area 1
                    if (cy >= ROW_AREA1_START && cy < ROW_AREA1_START + AREA1_ROWS)
                    {
                        int clicked = scroll_top + (cy - ROW_AREA1_START);
                        EnterCriticalSection(&state->lock);
                        int t = state->count;
                        LeaveCriticalSection(&state->lock);
                        if (clicked >= 0 && clicked < t) {
                            selected    = clicked;
                            auto_scroll = false;
                        }
                    }

                    // Click en botones
                    char btn = hit_menu_button(cx, cy);
                    if (btn) goto handle_action;
                    goto next_event;
                    handle_action:
                    {
                        switch (btn)
                        {
                        case 'Q':
                            state->running = false;
                            if (state->handle) pcap_breakloop(state->handle);
                            mouse_disable();
                            return;
                        case 'S':
                            if (state->running) {
                                state->want_restart = false;
                                state->running      = false;
                                if (state->handle) pcap_breakloop(state->handle);
                            } else {
                                state->want_restart = true; // main relanza el hilo
                                auto_scroll         = true;
                            }
                            prev_running = !state->running;
                            break;
                        case 'F':
                            ui_setup_filter(state);
                            restore_main_frame(cols);
                            auto_scroll  = true;
                            prev_running = !state->running;
                            break;
                        case 'C':
                            EnterCriticalSection(&state->lock);
                            state->count      = 0;
                            state->total_seen = 0;
                            state->running    = true;   // reanudar captura
                            LeaveCriticalSection(&state->lock);
                            selected     = 0;
                            scroll_top   = 0;
                            auto_scroll  = true;
                            prev_count   = -1;
                            prev_running = false;
                            invalidate_area1_cache();
                            break;
                        case 'E':
                            ui_do_export(state);
                            restore_main_frame(cols);
                            auto_scroll  = true;
                            prev_running = !state->running;
                            break;
                        }
                    }
                    next_event:;
                }

                // Rueda del mouse
                if (me.dwEventFlags == MOUSE_WHEELED)
                {
                    int delta = (int)(short)HIWORD(me.dwButtonState);
                    EnterCriticalSection(&state->lock);
                    int t = state->count;
                    LeaveCriticalSection(&state->lock);
                    if (delta > 0 && scroll_top > 0) {
                        scroll_top--;
                        selected    = scroll_top;
                        auto_scroll = false;
                    } else if (delta < 0 && scroll_top + AREA1_ROWS < t) {
                        scroll_top++;
                        selected    = scroll_top + AREA1_ROWS - 1;
                        auto_scroll = false;
                    }
                }
            }

            // ---- TECLADO ----
            if (ir.EventType == KEY_EVENT && ir.Event.KeyEvent.bKeyDown)
            {
                WORD vk = ir.Event.KeyEvent.wVirtualKeyCode;
                char ch = (char)toupper((unsigned char)ir.Event.KeyEvent.uChar.AsciiChar);

                if (vk == VK_UP) {
                    if (selected > 0) { selected--; auto_scroll = false; }
                    if (selected < scroll_top) scroll_top = selected;
                }
                else if (vk == VK_DOWN) {
                    EnterCriticalSection(&state->lock);
                    int t = state->count;
                    LeaveCriticalSection(&state->lock);
                    if (selected < t - 1) { selected++; auto_scroll = false; }
                    if (selected >= scroll_top + AREA1_ROWS)
                        scroll_top = selected - AREA1_ROWS + 1;
                }
                else if (ch == 'A') {
                    auto_scroll = true;
                }
                else if (ch == 'Q') {
                    state->running = false;
                    if (state->handle) pcap_breakloop(state->handle);
                    mouse_disable();
                    return;
                }
                else if (ch == 'S') {
                    if (state->running) {
                        state->want_restart = false;
                        state->running      = false;
                        if (state->handle) pcap_breakloop(state->handle);
                    } else {
                        state->want_restart = true;
                        auto_scroll         = true;
                    }
                    prev_running = !state->running;
                }
                else if (ch == 'F') {
                    ui_setup_filter(state);
                    restore_main_frame(cols);
                    auto_scroll  = true;
                    prev_running = !state->running;
                }
                else if (ch == 'C') {
                    EnterCriticalSection(&state->lock);
                    state->count      = 0;
                    state->total_seen = 0;
                    state->running    = true;
                    LeaveCriticalSection(&state->lock);
                    selected     = 0;
                    scroll_top   = 0;
                    auto_scroll  = true;
                    prev_count   = -1;
                    prev_running = false;
                    invalidate_area1_cache();
                }
                else if (ch == 'E') {
                    ui_do_export(state);
                    restore_main_frame(cols);
                    auto_scroll  = true;
                    prev_running = !state->running;
                }
            }
        }

        Sleep(80); // ~12 fps, suficiente sin parpadeo
    }
}