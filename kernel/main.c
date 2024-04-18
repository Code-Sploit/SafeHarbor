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
#include "../include/filter.h"
#include "../include/helper.h"
#include "../include/bridge.h"
#include "../include/main.h"
#include "../include/rule.h"

#define NIPQUAD(addr) \
    ((unsigned char *)&addr)[0], \
    ((unsigned char *)&addr)[1], \
    ((unsigned char *)&addr)[2], \
    ((unsigned char *)&addr)[3]

int TIME_BUF_SIZE = 32;

int FILTER_MATCH   = 1;
int FILTER_NOMATCH = 0;

struct tm current_time_value;

struct Rule rules[MAX_RULES];

struct mutex file_mutex;
struct mutex rule_mutex;

struct timespec64 tv;

char log_buf[LOG_BUF_SIZE];

spinlock_t log_lock;

int num_rules = 0;

int DO_SHOW_RULE_MISMATCHES = 0;
int DO_FILTERING = 1;
int DO_LOGGING = 1;

struct nf_hook_ops nf_ops[] = {
    {.hook = filter, .pf = NFPROTO_IPV4, .hooknum = NF_INET_PRE_ROUTING,  .priority = NF_IP_PRI_FIRST},
    {.hook = filter, .pf = NFPROTO_IPV4, .hooknum = NF_INET_LOCAL_IN,     .priority = NF_IP_PRI_FIRST},
    {.hook = filter, .pf = NFPROTO_IPV4, .hooknum = NF_INET_FORWARD,      .priority = NF_IP_PRI_FIRST},
    {.hook = filter, .pf = NFPROTO_IPV4, .hooknum = NF_INET_LOCAL_OUT,    .priority = NF_IP_PRI_FIRST},
    {.hook = filter, .pf = NFPROTO_IPV4, .hooknum = NF_INET_POST_ROUTING, .priority = NF_IP_PRI_FIRST},
};

static int __init firewall_init(void)
{
    int ret;

    printk(KERN_INFO "SafeHarbor: --------------------------------------------------");
    printk(KERN_INFO "SafeHarbor: Initialized\n");
    printk(KERN_INFO "SafeHarbor: Loading configuration\n");

    int bridge_ret = bridge_init();

    printk(KERN_INFO "SafeHarbor: Initializing IOCTL bridge [%s]\n", bridge_ret == 0 ? "success" : "failed");

    mutex_init(&file_mutex);
    mutex_init(&rule_mutex);

    spin_lock_init(&log_lock);

    ret = config_load();

    if (ret < 0)
    {
        printk(KERN_ERR "Failed to read configuration file\n");
        return ret;
    }

    printk(KERN_INFO "SafeHarbor: Configuration loaded\n");
    printk(KERN_INFO "SafeHarbor: Registering NetFilter hooks\n");

    for (int i = 0; i < ARRAY_SIZE(nf_ops); i++)
    {
        ret = nf_register_net_hook(&init_net, &nf_ops[i]);
        if (ret < 0)
        {
            printk(KERN_ERR "Failed to register Netfilter hook: %d\n", ret);
            return ret;
        }
    }

    printk(KERN_INFO "SafeHarbor: Registered NetFilter hooks\n");

    printk(KERN_INFO "SafeHarbor: --------------------------------------------------");
    printk(KERN_INFO "SafeHarbor: %s\n", " ____         __      _   _            _                ");
    printk(KERN_INFO "SafeHarbor: %s\n", "/ ___|  __ _ / _| ___| | | | __ _ _ __| |__   ___  _ __ ");
    printk(KERN_INFO "SafeHarbor: %s\n", "\\___ \\ / _` | |_ / _ \\ |_| |/ _` | '__| '_ \\ / _ \\| '__|");
    printk(KERN_INFO "SafeHarbor:  %s\n", "___) | (_| |  _|  __/  _  | (_| | |  | |_) | (_) | |   ");
    printk(KERN_INFO "SafeHarbor: %s\n", "|____/ \\__,_|_|  \\___|_| |_|\\__,_|_|  |_.__/ \\___/|_|");

    return 0;
}

static void __exit firewall_exit(void)
{
    printk(KERN_INFO "SafeHarbor: --------------------------------------------------");
    printk(KERN_INFO "SafeHarbor: Deregistering NetFilter hooks\n");
    printk(KERN_INFO "SafeHarbor: Deinitializing IOCTL bridge\n");

    bridge_deinit();

    for (int i = 0; i < ARRAY_SIZE(nf_ops); i++)
    {
        nf_unregister_net_hook(&init_net, &nf_ops[i]);
    }

    printk(KERN_INFO "SafeHarbor: Exited\n");

    mutex_destroy(&file_mutex);
    mutex_destroy(&rule_mutex);
}

module_init(firewall_init);
module_exit(firewall_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Samuel 't Hart");
MODULE_DESCRIPTION("A simple NetFilter firewall module");