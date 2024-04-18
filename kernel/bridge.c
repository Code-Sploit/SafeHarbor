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
#include "../include/bridge.h"
#include "../include/main.h"

#define MAX_STR_LEN 512

static struct file_operations bridge_options = {
    .owner          = THIS_MODULE,
    .open           = bridge_open,
    .release        = bridge_close,
    .unlocked_ioctl = bridge_ctl
};

int bridge_init()
{
    int ret = register_chrdev(BRIDGE_MAJOR, "safeharbor", &bridge_options);

    if (ret == 0)
    {
        printk(KERN_INFO "SafeHarbor: Registered device. [MAJOR: %d] [MINOR: %d]\n", BRIDGE_MAJOR, BRIDGE_MINOR);
    }
    else if (ret > 0)
    {
        printk(KERN_INFO "SafeHarbor: Registered device. [MAJOR: %d] [MINOR: %d]\n", ret >> 20, ret & 0xfffff);
    }
    else
    {
        printk(KERN_ERR "SafeHarbor: Failed to register device.\n");

        return -1;
    }

    return 0;
}

int bridge_deinit()
{
    unregister_chrdev(BRIDGE_MAJOR, "safeharbor");

    return 0;
}

int bridge_open(struct inode *device, struct file *instance)
{
    /* Callback function when the device is opened */

    printk(KERN_INFO "SafeHarbor: IOCTL bridge_open() was called\n");

    return 0;
}

int bridge_close(struct inode *device, struct file *instance)
{
    /* Callback function when the device is closed */

    printk(KERN_INFO "SafeHarbor: IOCTL bridge_close() was called\n");

    return 0;
}

long int bridge_ctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    char *arg_str = kmalloc(MAX_STR_LEN, GFP_KERNEL); // Allocate memory for the argument string

    if (!arg_str) {
        return -ENOMEM;
    }

    int copy = copy_from_user(arg_str, (char *) arg, MAX_STR_LEN);

    int exit = 0;

    // Handle different ioctl commands
    switch (cmd)
    {
        case BRIDGE_FILTER_SET:
            if (strcmp(arg_str, "on") == 0)
            {
                DO_FILTERING = 1;
            }
            else if (strcmp(arg_str, "off") == 0)
            {
                DO_FILTERING = 0;
            }
            else
            {
                printk(KERN_INFO "SafeHarbor: Invalid value for setting DO_FILTERING\n");
            }

            break;
        
        case BRIDGE_LOGGING_SET:
            if (strcmp(arg_str, "on") == 0 )
            {
                DO_LOGGING = 1;
            }
            else if (strcmp(arg_str, "off") == 0)
            {
                DO_LOGGING = 0;
            }
            else
            {
                printk(KERN_INFO "SafeHarbor: Invalid value for setting DO_LOGGING\n");
            }

            break;
        
        case BRIDGE_MISMATCH_SET:
            if (strcmp(arg_str, "on") == 0 )
            {
                DO_SHOW_RULE_MISMATCHES = 1;
            }
            else if (strcmp(arg_str, "off") == 0)
            {
                DO_SHOW_RULE_MISMATCHES = 0;
            }
            else
            {
                printk(KERN_INFO "SafeHarbor: Invalid value for setting DO_SHOW_RULE_MISMATCHES\n");
            }

            break;
        
        case BRIDGE_CONFIG_RELOAD:
            num_rules = 0;

            int ret = config_load();

            printk(KERN_INFO "SafeHarbor: Configuration was reloaded [%s]\n", (ret == 0) ? "success" : "failed");

            break;

        default:
            kfree(arg_str); // Free allocated memory

            return -EINVAL; // Invalid argument
    }

    kfree(arg_str); // Free allocated memory

    return exit;
}