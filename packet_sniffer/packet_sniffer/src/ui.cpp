/*
 * ui.cpp
 * Text-based user interface.
 *
 * Layout (console window):
 * +---------------------------------------------------------+
 * | MENU BAR                                                |
 * +---------------------------------------------------------+
 * | AREA 1 - Captured traffic list (scrollable)             |
 * |   #  | Time     | Src IP          | Dst IP         |...|
 * +---------------------------------------------------------+
 * | AREA 2 - Structured packet detail of selected row       |
 * +---------------------------------------------------------+
 * | AREA 3 - Raw hex dump of selected packet                |
 * +---------------------------------------------------------+
 * | STATUS BAR                                              |
 * +---------------------------------------------------------+
 *
 * Controls:
 *   UP/DOWN  - scroll Area 1
 *   S        - Start/Stop capture
 *   F        - Set filter menu
 *   E        - Export to CSV
 *   C        - Clear capture buffer
 *   Q        - Quit
 */

#include "../include/sniffer.h"
#include <string>

// -----------------------------------------------------------------------
// Console helpers
// -----------------------------------------------------------------------

void ui_clear_screen(void)
{
    HANDLE hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
    COORD coordScreen = {0, 0};
    DWORD cCharsWritten;
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    DWORD dwConSize;

    GetConsoleScreenBufferInfo(hStdout, &csbi);
    dwConSize = csbi.dwSize.X * csbi.dwSize.Y;
    FillConsoleOutputCharacter(hStdout, ' ', dwConSize, coordScreen, &cCharsWritten);
    FillConsoleOutputAttribute(hStdout, csbi.wAttributes, dwConSize, coordScreen, &cCharsWritten);
    SetConsoleCursorPosition(hStdout, coordScreen);
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

static void print_hline(int cols, WORD color)
{
    set_color(color);
    for (int i = 0; i < cols; i++) putchar('-');
    putchar('\n');
}

static void hide_cursor(void)
{
    CONSOLE_CURSOR_INFO ci = {1, FALSE};
    SetConsoleCursorInfo(GetStdHandle(STD_OUTPUT_HANDLE), &ci);
}

// -----------------------------------------------------------------------
// Area 1: traffic list
// -----------------------------------------------------------------------
void ui_print_area1(const sniffer_state_t *state, int selected, int scroll_top)
{
    int cols, rows;
    ui_get_console_size(&cols, &rows);

    // Header row
    set_color(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    printf("  %-5s %-10s %-16s %-16s %-6s %-6s %-6s %-7s\n",
           "#", "Time", "Src IP", "Dst IP",
           "SPort", "DPort", "Proto", "Len");
    set_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);

    // How many rows available for Area 1 (rough: 10 lines)
    int area1_rows = 10;

    EnterCriticalSection((CRITICAL_SECTION *)&state->lock);
    int total = state->count;

    for (int i = 0; i < area1_rows; i++)
    {
        int idx = scroll_top + i;
        if (idx >= total)
        {
            printf("\n");
            continue;
        }

        int slot = idx % MAX_PACKETS;
        const packet_record_t *rec = &state->packets[slot];

        if (idx == selected)
            set_color(BACKGROUND_BLUE | FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
        else
        {
            // Color by protocol
            if (rec->protocol == PROTO_TCP)
                set_color(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
            else if (rec->protocol == PROTO_UDP)
                set_color(FOREGROUND_RED | FOREGROUND_GREEN);
            else if (rec->protocol == PROTO_ICMP)
                set_color(FOREGROUND_RED | FOREGROUND_INTENSITY);
            else
                set_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        }

        printf("  %-5d %-10s %-16s %-16s %-6d %-6d %-6s %-7d\n",
               rec->index,
               rec->time_str,
               rec->src_ip,
               rec->dst_ip,
               rec->src_port,
               rec->dst_port,
               rec->proto_str,
               rec->total_len);
    }
    LeaveCriticalSection((CRITICAL_SECTION *)&state->lock);

    set_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
}

// -----------------------------------------------------------------------
// Area 2: structured packet detail
// -----------------------------------------------------------------------
void ui_print_area2(const packet_record_t *rec)
{
    if (!rec)
    {
        printf("  (no packet selected)\n\n\n\n");
        return;
    }

    set_color(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    printf("  [IP]  ");
    set_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    printf("Src: %-16s  Dst: %-16s  ID: %-6d  TTL: %-4d  TOS: 0x%02X  Len: %d\n",
           rec->src_ip, rec->dst_ip, rec->ip_id, rec->ttl, rec->tos, rec->total_len);

    if (rec->protocol == PROTO_TCP)
    {
        set_color(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        printf("  [TCP] ");
        set_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        printf("SPort: %-6d  DPort: %-6d  Seq: %-12u  Ack: %-12u  Flags: %c%c%c%c%c%c\n",
               rec->src_port, rec->dst_port,
               rec->tcp_seq, rec->tcp_ack,
               (rec->tcp_flags & TCP_SYN) ? 'S' : '-',
               (rec->tcp_flags & TCP_ACK) ? 'A' : '-',
               (rec->tcp_flags & TCP_FIN) ? 'F' : '-',
               (rec->tcp_flags & TCP_RST) ? 'R' : '-',
               (rec->tcp_flags & TCP_PSH) ? 'P' : '-',
               (rec->tcp_flags & TCP_URG) ? 'U' : '-');
    }
    else if (rec->protocol == PROTO_UDP)
    {
        set_color(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        printf("  [UDP] ");
        set_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        printf("SPort: %-6d  DPort: %-6d\n", rec->src_port, rec->dst_port);
    }
    else if (rec->protocol == PROTO_ICMP)
    {
        set_color(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        printf("  [ICMP]");
        set_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        printf(" Type: %-4d  Code: %-4d\n", rec->icmp_type, rec->icmp_code);
    }
    else
    {
        printf("  [PROTO %d] (no parsed detail)\n", rec->protocol);
    }

    // Extra padding lines to keep layout stable
    printf("\n");
}

// -----------------------------------------------------------------------
// Area 3: raw hex + ASCII dump
// -----------------------------------------------------------------------
void ui_print_area3(const packet_record_t *rec)
{
    if (!rec || rec->raw_len == 0)
    {
        printf("  (no data)\n\n");
        return;
    }

    set_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    printf("  Offset   00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F   ASCII\n");
    set_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);

    int bytes_to_show = rec->raw_len > 64 ? 64 : rec->raw_len; // show up to 4 rows
    for (int i = 0; i < bytes_to_show; i += 16)
    {
        // Offset
        set_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        printf("  %04X     ", i);
        set_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);

        // Hex
        for (int j = 0; j < 16; j++)
        {
            if (i + j < bytes_to_show)
                printf("%02X ", rec->raw[i + j]);
            else
                printf("   ");
            if (j == 7) printf(" ");
        }

        // ASCII
        printf("  ");
        for (int j = 0; j < 16 && (i + j) < bytes_to_show; j++)
        {
            unsigned char c = rec->raw[i + j];
            putchar((c >= 32 && c < 127) ? c : '.');
        }
        putchar('\n');
    }
}

// -----------------------------------------------------------------------
// Menu / status bar
// -----------------------------------------------------------------------
void ui_print_menu(const sniffer_state_t *state)
{
    set_color(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    printf("  [S]tart/Stop  [F]ilter  [E]xport CSV  [C]lear  [Q]uit   ");
    set_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);

    const char *status = state->running ? "CAPTURING" : "STOPPED";
    WORD sc = state->running
        ? (FOREGROUND_GREEN | FOREGROUND_INTENSITY)
        : (FOREGROUND_RED   | FOREGROUND_INTENSITY);
    set_color(sc);
    printf("%-10s", status);
    set_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);

    printf("  Pkts: %d / %d", state->count, state->total_seen);
    if (state->filter.active)
    {
        set_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        printf("  [FILTER ON]");
        set_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    }
    printf("\n");
}

// -----------------------------------------------------------------------
// Filter setup dialog (inline, blocking)
// -----------------------------------------------------------------------
static void ui_setup_filter(sniffer_state_t *state)
{
    ui_clear_screen();
    set_color(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    printf("\n  === FILTER SETUP ===\n");
    set_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    printf("  Leave blank to skip that filter.\n\n");

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
    fgets(buf, sizeof(buf), stdin);
    f.src_port = atoi(buf);

    printf("  Dest Port      : "); fflush(stdout);
    fgets(buf, sizeof(buf), stdin);
    f.dst_port = atoi(buf);

    printf("  Protocol (0=any, 1=ICMP, 6=TCP, 17=UDP): "); fflush(stdout);
    fgets(buf, sizeof(buf), stdin);
    f.protocol = atoi(buf);

    f.active = (f.src_ip[0] != '\0' || f.dst_ip[0] != '\0' ||
                f.src_port  != 0    || f.dst_port  != 0     ||
                f.protocol  != 0);

    EnterCriticalSection(&state->lock);
    state->filter = f;
    LeaveCriticalSection(&state->lock);
}

// -----------------------------------------------------------------------
// Main UI loop
// -----------------------------------------------------------------------
void ui_run(sniffer_state_t *state)
{
    hide_cursor();

    int selected   = 0;
    int scroll_top = 0;
    const int area1_rows = 10;

    // Redraw every ~200ms or on keypress
    while (true)
    {
        // --- Redraw ---
        gotoxy(0, 0);

        int cols, rows;
        ui_get_console_size(&cols, &rows);

        // Title
        set_color(BACKGROUND_BLUE | FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
        printf("  PACKET SNIFFER  -  Redes I  -  Npcap                                              \n");
        set_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);

        // Menu
        ui_print_menu(state);
        print_hline(cols, FOREGROUND_GREEN);

        // Area 1
        set_color(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        printf("  AREA 1 - Captured Traffic\n");
        set_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);

        EnterCriticalSection(&state->lock);
        int total = state->count;
        // Auto-scroll: keep selected visible
        if (selected >= total && total > 0)
            selected = total - 1;
        if (selected < scroll_top)
            scroll_top = selected;
        if (selected >= scroll_top + area1_rows)
            scroll_top = selected - area1_rows + 1;

        // Get selected record pointer (copy while locked)
        packet_record_t sel_rec;
        bool has_sel = false;
        if (total > 0 && selected >= 0 && selected < total)
        {
            sel_rec = state->packets[selected % MAX_PACKETS];
            has_sel = true;
        }
        LeaveCriticalSection(&state->lock);

        ui_print_area1(state, selected, scroll_top);

        print_hline(cols, FOREGROUND_GREEN);
        set_color(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        printf("  AREA 2 - Packet Detail  (packet #%d)\n", has_sel ? sel_rec.index : 0);
        set_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        ui_print_area2(has_sel ? &sel_rec : NULL);

        print_hline(cols, FOREGROUND_GREEN);
        set_color(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        printf("  AREA 3 - Raw Hex Dump\n");
        set_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        ui_print_area3(has_sel ? &sel_rec : NULL);

        print_hline(cols, FOREGROUND_GREEN);

        // --- Handle input (non-blocking check) ---
        if (_kbhit())
        {
            int ch = _getch();
            if (ch == 0 || ch == 0xE0) // special key prefix
            {
                int ch2 = _getch();
                if (ch2 == 72) // Up arrow
                {
                    if (selected > 0) selected--;
                }
                else if (ch2 == 80) // Down arrow
                {
                    EnterCriticalSection(&state->lock);
                    if (selected < state->count - 1) selected++;
                    LeaveCriticalSection(&state->lock);
                }
            }
            else
            {
                ch = toupper(ch);
                switch (ch)
                {
                    case 'Q':
                        // Signal capture thread to stop
                        state->running = false;
                        if (state->handle)
                            pcap_breakloop(state->handle);
                        return;

                    case 'S':
                        // Toggle capture (simple: stop only; start requires restart)
                        if (state->running)
                        {
                            state->running = false;
                            if (state->handle)
                                pcap_breakloop(state->handle);
                        }
                        else
                        {
                            // Re-arm: signal main to restart thread
                            state->running = true;
                        }
                        break;

                    case 'F':
                        ui_setup_filter(state);
                        break;

                    case 'C':
                        EnterCriticalSection(&state->lock);
                        state->count      = 0;
                        state->total_seen = 0;
                        selected   = 0;
                        scroll_top = 0;
                        LeaveCriticalSection(&state->lock);
                        break;

                    case 'E':
                    {
                        // Ask for filename
                        ui_clear_screen();
                        set_color(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                        printf("\n  Export to CSV\n");
                        set_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
                        printf("  Filename [capture.csv]: ");
                        fflush(stdout);
                        char fname[256] = "capture.csv";
                        fgets(fname, sizeof(fname), stdin);
                        fname[strcspn(fname, "\r\n")] = '\0';
                        if (fname[0] == '\0')
                            strcpy(fname, "capture.csv");

                        extern bool export_csv(const sniffer_state_t *, const char *);
                        if (export_csv(state, fname))
                        {
                            set_color(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                            printf("  Exported to %s\n", fname);
                        }
                        else
                        {
                            set_color(FOREGROUND_RED | FOREGROUND_INTENSITY);
                            printf("  Export FAILED.\n");
                        }
                        set_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
                        printf("  Press any key...\n");
                        _getch();
                        break;
                    }
                }
            }
        }

        Sleep(150); // refresh ~6 fps
    }
}
