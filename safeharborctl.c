#include <sys/ioctl.h>

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>

#include "safeharbor.h"

int main(int argc, char **argv)
{
    int device = open("/dev/safeharbor", O_RDWR);

    if (device == -1)
    {
        perror("SafeHarbor: Failed to open IOCTL bridge\n");

        return -1;
    }
    
    if (argc < 2)
    {
        printf("SafeHarbor: Usage: safeharborctl <action> <rule/on/off> <flags>\n");

        return -1;
    }

    char *action = argv[1];
    char *arg    = argv[2];

    if (strcmp(action, "filter") == 0)
    {
        printf("SafeHarbor: filter -> %s\n", arg);

        ioctl(device, BRIDGE_FILTER_SET, arg);
    }
    else if (strcmp(action, "log") == 0)
    {
        printf("SafeHarbor: logging -> %s\n", arg);

        ioctl(device, BRIDGE_LOGGING_SET, arg);
    }
    else if (strcmp(action, "mismatch") == 0)
    {
        printf("SafeHarbor: mismatch -> %s\n", arg);

        ioctl(device, BRIDGE_MISMATCH_SET, arg);
    }
    else
    {
        printf("SafeHarbor: Invalid action\n");
    }

    printf("SafeHarbor: Success\n");

    close(device);

    return 0;
}