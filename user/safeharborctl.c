#include <sys/ioctl.h>

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>

#include "../include/safeharbor.h"

#define KERNEL_MODULE_PATH "/usr/share/safeharbor/safeharbor.ko"

int main(int argc, char **argv)
{    
    if (argc < 2)
    {
        printf("SafeHarbor: Usage: safeharborctl <action> [rule/on/off] [flags]\n");

        return -1;
    }

    char *action = argv[1];

    if (strcmp(action, "enable") == 0)
    {
        int ret = system("insmod /usr/share/safeharbor/safeharbor.ko > /dev/null");

        printf("SafeHarbor: %s\n", (ret == 0) ? "success" : "failed");

        return ret;
    }
    else if (strcmp(action, "disable") == 0)
    {
        int ret = system("rmmod /usr/share/safeharbor/safeharbor.ko > /dev/null");

        printf("SafeHarbor: %s\n", (ret == 0) ? "success" : "failed");

        return ret;
    }
    else if (strcmp(action, "reload") == 0)
    {
        int ret_rm = 0;
        int ret_in = 0;
        
        ret_rm = system("rmmod /usr/share/safeharbor/safeharbor.ko > /dev/null");
        ret_in = system("insmod /usr/share/safeharbor/safeharbor.ko > /dev/null");

        int ret = ret_rm + ret_in;

        printf("SafeHarbor: %s\n", (ret == 0) ? "success" : "failed");

        return ret;
    }

    int device = open("/dev/safeharbor", O_RDWR);

    if (device == -1)
    {
        perror("SafeHarbor: Failed to open IOCTL bridge\n");

        return -1;
    
    }
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