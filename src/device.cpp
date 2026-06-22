

#include "../include/sniffer.h"

int list_devices(pcap_if_t **all_devs, char *errbuf)
{
    if (pcap_findalldevs(all_devs, errbuf) == -1)
        return -1;

    int count = 0;
    for (pcap_if_t *d = *all_devs; d != NULL; d = d->next)
        count++;
    return count;
}

int select_device(pcap_if_t *all_devs)
{
    int count = 0;
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(h, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    printf("\n  Available network interfaces:\n\n");
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
        printf("  No interfaces found. Run as Administrator.\n");
        return -1;
    }

    int choice = 0;
    while (choice < 1 || choice > count)
    {
        SetConsoleTextAttribute(h, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        printf("  Select interface [1-%d]: ", count);
        SetConsoleTextAttribute(h, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        scanf("%d", &choice);
        int c; while ((c = getchar()) != '\n' && c != EOF);
    }
    return choice;
}
