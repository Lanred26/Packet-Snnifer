/*
 * main.cpp
 * Packet Sniffer - Proyecto Redes I
 *
 * Build (MinGW / MSYS2):
 *   g++ -std=c++11 -o sniffer.exe src/main.cpp src/capture.cpp src/ui.cpp \
 *       src/export.cpp src/device.cpp \
 *       -I include -I "C:/Program Files/Npcap/sdk/Include" \
 *       -L "C:/Program Files/Npcap/sdk/Lib/x64" \
 *       -lwpcap -lws2_32 -lIPHlpApi
 *
 * Must be run as Administrator so Npcap can open the adapter.
 */

#include "../include/sniffer.h"

// -----------------------------------------------------------------------
// main
// -----------------------------------------------------------------------
int main(void)
{
// Enable ANSI escape sequences on Windows 10+
#ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
#define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
#endif
HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
DWORD dwMode = 0;
GetConsoleMode(hOut, &dwMode);
SetConsoleMode(hOut, dwMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    // Winsock init (needed for inet_ntoa on some Windows versions)
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    // ----------------------------------------------------------------
    // Banner
    // ----------------------------------------------------------------
    ui_clear_screen();
    SetConsoleTextAttribute(hOut, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    printf("\n");
    printf("  ==========================================\n");
    printf("       PACKET SNIFFER  -  Redes I\n");
    printf("       Powered by Npcap\n");
    printf("  ==========================================\n\n");
    SetConsoleTextAttribute(hOut, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);

    // ----------------------------------------------------------------
    // Enumerate network devices
    // ----------------------------------------------------------------
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *all_devs = NULL;

    int dev_count = list_devices(&all_devs, errbuf);
    if (dev_count <= 0)
    {
        fprintf(stderr, "\n  ERROR listing devices: %s\n", errbuf);
        fprintf(stderr, "  Make sure Npcap is installed and run as Administrator.\n");
        WSACleanup();
        return 1;
    }

    int choice = select_device(all_devs);
    if (choice < 1)
    {
        pcap_freealldevs(all_devs);
        WSACleanup();
        return 1;
    }

    // Get the chosen device name
    pcap_if_t *dev = all_devs;
    for (int i = 1; i < choice; i++)
        dev = dev->next;

    char dev_name[256];
    strncpy(dev_name, dev->name, sizeof(dev_name) - 1);
    dev_name[sizeof(dev_name) - 1] = '\0';

    pcap_freealldevs(all_devs);

    // ----------------------------------------------------------------
    // Open the device for capture
    // ----------------------------------------------------------------
    // BUFSIZ snapshot, promiscuous mode ON (1), 1000ms timeout
    pcap_t *handle = pcap_open_live(dev_name, 65535, 1, 1000, errbuf);
    if (!handle)
    {
        fprintf(stderr, "\n  ERROR opening device: %s\n", errbuf);
        WSACleanup();
        return 1;
    }

    // We only handle Ethernet links
    if (pcap_datalink(handle) != DLT_EN10MB)
    {
        fprintf(stderr, "\n  ERROR: Only Ethernet (DLT_EN10MB) adapters are supported.\n");
        pcap_close(handle);
        WSACleanup();
        return 1;
    }

    // ----------------------------------------------------------------
    // Initialize global state
    // ----------------------------------------------------------------
    sniffer_state_t state;
    memset(&state, 0, sizeof(state));
    state.handle  = handle;
    state.running = true;
    InitializeCriticalSection(&state.lock);

    // ----------------------------------------------------------------
    // Launch capture thread
    // ----------------------------------------------------------------
    HANDLE hThread = CreateThread(NULL, 0, capture_thread, &state, 0, NULL);
    if (!hThread)
    {
        fprintf(stderr, "\n  ERROR: Could not create capture thread.\n");
        pcap_close(handle);
        DeleteCriticalSection(&state.lock);
        WSACleanup();
        return 1;
    }

    // ----------------------------------------------------------------
    // Run UI (blocking, returns on Q press)
    // ----------------------------------------------------------------
    ui_run(&state);

    // ----------------------------------------------------------------
    // Cleanup
    // ----------------------------------------------------------------
    state.running = false;
    pcap_breakloop(handle);
    WaitForSingleObject(hThread, 3000);
    CloseHandle(hThread);

    pcap_close(handle);
    DeleteCriticalSection(&state.lock);
    WSACleanup();

    ui_clear_screen();
    SetConsoleTextAttribute(hOut, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    printf("\n  Capture stopped. Goodbye.\n\n");
    SetConsoleTextAttribute(hOut, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);

    return 0;
}
