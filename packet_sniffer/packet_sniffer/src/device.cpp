/*
 * device.cpp
 * Network interface enumeration and selection via Npcap.
 */

#include "../include/sniffer.h"

// -----------------------------------------------------------------------
// list_devices: wraps pcap_findalldevs
// Returns number of devices found, or -1 on error.
// Caller must call pcap_freealldevs(all_devs) when done.
// -----------------------------------------------------------------------
int list_devices(pcap_if_t **all_devs, char *errbuf)
{
    if (pcap_findalldevs(all_devs, errbuf) == -1)
        return -1;

    int count = 0;
    for (pcap_if_t *d = *all_devs; d != NULL; d = d->next)
        count++;

    return count;
}

// -----------------------------------------------------------------------
// select_device: prints numbered list and asks user to pick one.
// Returns 1-based index of chosen device, or -1 on error.
// -----------------------------------------------------------------------
int select_device(pcap_if_t *all_devs)
{
    int count = 0;

    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(h, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    printf("\n  Interfaces de red disponibles:\n\n");
    SetConsoleTextAttribute(h, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);

    for (pcap_if_t *d = all_devs; d != NULL; d = d->next)
    {
        count++;
        SetConsoleTextAttribute(h, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        printf("  [%2d] ", count);
        SetConsoleTextAttribute(h, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        printf("%s", d->name);

        if (d->description)
            printf("\n       %s", d->description);

        // Print first IPv4 address if available
        for (pcap_addr_t *a = d->addresses; a != NULL; a = a->next)
        {
            if (a->addr && a->addr->sa_family == AF_INET)
            {
                struct sockaddr_in *sin = (struct sockaddr_in *)a->addr;
                printf("\n       IP: %s", inet_ntoa(sin->sin_addr));
                break;
            }
        }
        printf("\n\n");
    }

    if (count == 0)
    {
        printf("  Sin interfaces disponibles. eje como administrador.\n");
        return -1;
    }

    int choice = 0;
    while (choice < 1 || choice > count)
    {
        SetConsoleTextAttribute(h, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        printf("  Seleccionar interfas [1-%d]: ", count);
        SetConsoleTextAttribute(h, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        scanf("%d", &choice);
        // Clear stdin
        int c; while ((c = getchar()) != '\n' && c != EOF);
    }

    return choice;
}
