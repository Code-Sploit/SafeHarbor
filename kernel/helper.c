#include <linux/netfilter_ipv4.h>
#include <linux/buffer_head.h>
#include <linux/netfilter.h>
#include <linux/fs_struct.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/ioctl.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/cred.h>
#include <linux/path.h>
#include <linux/file.h>
#include <linux/time.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <linux/fs.h>
#include <linux/in.h>

#include "../include/constants.h"
#include "../include/helper.h"

char *get_current_time_string(void)
{
    static char datetime[256];

    ktime_get_real_ts64(&tv);
    time64_to_tm(tv.tv_sec, 0, &current_time_value);
    
    snprintf(datetime, TIME_BUF_SIZE, "%04ld-%02d-%02d %02d:%02d:%02d",
             current_time_value.tm_year + 1900, current_time_value.tm_mon + 1, current_time_value.tm_mday,
             current_time_value.tm_hour, current_time_value.tm_min, current_time_value.tm_sec);
    
    return datetime;
}

char *ip_ntoa(unsigned int ip)
{
    static char ip_str[16];
 
    sprintf(ip_str, "%u.%u.%u.%u",
            ip & 0xFF,
            (ip >> 8) & 0xFF,
            (ip >> 16) & 0xFF,
            (ip >> 24) & 0xFF);
 
    return ip_str;
}

void remove_whitespaces(char *str)
{
    int i = 0;
    int j = 0;

    // Find the index of the first non-whitespace character
    while (str[i] == ' ') {
        i++;
    }

    // Shift the string to remove leading whitespaces
    while (str[i] != '\0') {
        str[j] = str[i];
        i++;
        j++;
    }

    // Null-terminate the string at the new end
    str[j] = '\0';
}

int atoi(const char *str)
{
    int res = 0;
    int sign = 1;
    int i = 0;

    // Skip white spaces
    while (str[i] == ' ')
        i++;

    // Handle sign
    if (str[i] == '-') {
        sign = -1;
        i++;
    }

    // Process digits
    while (str[i] >= '0' && str[i] <= '9') {
        res = res * 10 + (str[i] - '0');
        i++;
    }

    // Apply sign
    return sign * res;
}

void get_until_delim(char *buffer, char *str, char delim)
{
    int i = 0;

    while (str[i] != delim)
    {
        buffer[i] = str[i];

        i++;
    }

    buffer[i] = '\0';
}

MODULE_LICENSE("GPL");