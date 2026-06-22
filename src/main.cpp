/*
 * main.cpp
 * Packet Sniffer - Proyecto Redes I
 *
 * Build:
 *   g++ -std=c++11 -Wall -O2 src/main.cpp src/capture.cpp src/ui.cpp \
 *       src/export.cpp src/device.cpp src/nodes.cpp \
 *       -I include \
 *       -I "C:\Uni\redes\npcap-sdk-1.13\Include" \
 *       -L "C:\Uni\redes\npcap-sdk-1.13\Lib" \
 *       -o sniffer.exe -lwpcap -lws2_32 -lIPHlpApi
 *
 * Ejecutar como Administrador.
 */

#include "../include/sniffer.h"

// -----------------------------------------------------------------------
// Hilo de la UI
// -----------------------------------------------------------------------
static DWORD WINAPI ui_thread_proc(LPVOID arg)
{
    ui_run((sniffer_state_t *)arg);
    return 0;
}

// -----------------------------------------------------------------------
// Lanza un nuevo hilo de captura, cerrando el anterior si existe.
// Necesario porque pcap_breakloop deja el handle pcap inutilizable.
// -----------------------------------------------------------------------
static HANDLE launch_capture(sniffer_state_t *state, HANDLE prev_thread,
                              const char *dev_name, char *errbuf)
{
    if (prev_thread != NULL) {
        WaitForSingleObject(prev_thread, 2000);
        CloseHandle(prev_thread);
    }

    if (state->handle) {
        pcap_close(state->handle);
        state->handle = NULL;
    }

    pcap_t *handle = pcap_open_live(dev_name, 65535, 1, 1000, errbuf);
    if (!handle) return NULL;

    if (pcap_datalink(handle) != DLT_EN10MB) {
        pcap_close(handle);
        return NULL;
    }

    state->handle       = handle;
    state->running      = true;
    state->want_restart = false;

    HANDLE hThread = CreateThread(NULL, 0, capture_thread, state, 0, NULL);
    if (!hThread) {
        pcap_close(handle);
        state->handle = NULL;
    }
    return hThread;
}

// -----------------------------------------------------------------------
// main
// -----------------------------------------------------------------------
int main(void)
{
#ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
#define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
#endif
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD dwMode = 0;
    GetConsoleMode(hOut, &dwMode);
    SetConsoleMode(hOut, dwMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);

    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    ui_clear_screen();
    SetConsoleTextAttribute(hOut, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    printf("\n");
    printf("  ==========================================\n");
    printf("       PACKET SNIFFER  -  Redes I\n");
    printf("       Powered by Npcap\n");
    printf("  ==========================================\n\n");
    SetConsoleTextAttribute(hOut, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *all_devs = NULL;

    int dev_count = list_devices(&all_devs, errbuf);
    if (dev_count <= 0) {
        fprintf(stderr, "\n  ERROR: %s\n  Ejecutar como Administrador.\n", errbuf);
        WSACleanup();
        return 1;
    }

    int choice = select_device(all_devs);
    if (choice < 1) { pcap_freealldevs(all_devs); WSACleanup(); return 1; }

    pcap_if_t *dev = all_devs;
    for (int i = 1; i < choice; i++) dev = dev->next;

    char dev_name[256];
    strncpy(dev_name, dev->name, sizeof(dev_name) - 1);
    dev_name[sizeof(dev_name) - 1] = '\0';
    pcap_freealldevs(all_devs);

    sniffer_state_t state;
    memset(&state, 0, sizeof(state));
    InitializeCriticalSection(&state.lock);
    InitializeCriticalSection(&state.node_lock);

    HANDLE hThread = launch_capture(&state, NULL, dev_name, errbuf);
    if (!hThread) {
        fprintf(stderr, "\n  ERROR abriendo dispositivo: %s\n", errbuf);
        DeleteCriticalSection(&state.lock);
        DeleteCriticalSection(&state.node_lock);
        WSACleanup();
        return 1;
    }

    HANDLE hUI = CreateThread(NULL, 0, ui_thread_proc, &state, 0, NULL);

    if (!hUI) {
        ui_run(&state);
    } else {
        while (WaitForSingleObject(hUI, 100) == WAIT_TIMEOUT)
        {
            if (state.want_restart)
            {
                hThread = launch_capture(&state, hThread, dev_name, errbuf);
                if (!hThread) {
                    state.running      = false;
                    state.want_restart = false;
                }
            }
        }
        CloseHandle(hUI);
    }

    state.running = false;
    if (state.handle) pcap_breakloop(state.handle);
    if (hThread) {
        WaitForSingleObject(hThread, 3000);
        CloseHandle(hThread);
    }
    if (state.handle) { pcap_close(state.handle); state.handle = NULL; }
    DeleteCriticalSection(&state.lock);
    DeleteCriticalSection(&state.node_lock);
    WSACleanup();

    ui_clear_screen();
    SetConsoleTextAttribute(hOut, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    printf("\n  Captura detenida. Hasta luego.\n\n");
    SetConsoleTextAttribute(hOut, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    return 0;
}
