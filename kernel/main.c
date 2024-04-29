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
#include "../include/spi.h"

void print_configuration(struct Configuration *configuration);

#define NIPQUAD(addr) \
    ((unsigned char *)&addr)[0], \
    ((unsigned char *)&addr)[1], \
    ((unsigned char *)&addr)[2], \
    ((unsigned char *)&addr)[3]

int TIME_BUF_SIZE = 32;

int FILTER_MATCH   = 1;
int FILTER_NOMATCH = 0;

struct tm current_time_value;

struct Configuration *configuration;

struct mutex file_mutex;
struct mutex rule_mutex;

struct timespec64 tv;

char log_buf[LOG_BUF_SIZE];

spinlock_t log_lock;

int CONFIG_DEFAULT_FILTER   = 1;
int CONFIG_DEFAULT_LOG      = 1;
int CONFIG_DEFAULT_MISMATCH = 0;

struct SPIConnectionManager *spi_connection_manager;

struct nf_hook_ops nf_ops[] = {   
    {.hook = filter, .pf = NFPROTO_IPV4, .hooknum = NF_INET_PRE_ROUTING,  .priority = NF_IP_PRI_FIRST},
    {.hook = filter, .pf = NFPROTO_IPV4, .hooknum = NF_INET_LOCAL_IN,     .priority = NF_IP_PRI_FIRST},
    {.hook = filter, .pf = NFPROTO_IPV4, .hooknum = NF_INET_FORWARD,      .priority = NF_IP_PRI_FIRST},
    {.hook = filter, .pf = NFPROTO_IPV4, .hooknum = NF_INET_LOCAL_OUT,    .priority = NF_IP_PRI_FIRST},
    {.hook = filter, .pf = NFPROTO_IPV4, .hooknum = NF_INET_POST_ROUTING, .priority = NF_IP_PRI_FIRST},
};

void print_configuration(struct Configuration *configuration) {
    int i, j;

    // Print rules in groups
    for (i = 0; i < configuration->group_count; i++) {
        printk(KERN_INFO "SafeHarbor: Group [%s] Rules:\n", configuration->groups[i]->name);
        for (j = 0; j < configuration->groups[i]->rule_count; j++) {
            printk(KERN_INFO "SafeHarbor: Rule: %s %s %s from %s port %s to %s port %s\n",
                   configuration->groups[i]->rules[j]->action ? "deny" : "allow",
                   configuration->groups[i]->rules[j]->protocol,
                   configuration->groups[i]->rules[j]->direction ? "in" : "out",
                   configuration->groups[i]->rules[j]->src,
                   configuration->groups[i]->rules[j]->sport,
                   configuration->groups[i]->rules[j]->dst,
                   configuration->groups[i]->rules[j]->dport);
        }
    }

    // Print individual rules
    printk(KERN_INFO "SafeHarbor: Individual Rules:\n");
    for (i = 0; i < configuration->rule_count; i++) {
        printk(KERN_INFO "SafeHarbor: Rule: %s %s %s from %s port %s to %s port %s\n",
               configuration->rules[i]->action ? "deny" : "allow",
               configuration->rules[i]->protocol,
               configuration->rules[i]->direction ? "in" : "out",
               configuration->rules[i]->src,
               configuration->rules[i]->sport,
               configuration->rules[i]->dst,
               configuration->rules[i]->dport);
    }
}


static int __init firewall_init(void)
{
    int ret;

    printk(KERN_INFO "SafeHarbor: --------------------------------------------------");
    printk(KERN_INFO "SafeHarbor: Initialized\n");
    printk(KERN_INFO "SafeHarbor: Loading configuration\n");

    configuration = configuration_initialize(CONFIG_DEFAULT_FILTER, CONFIG_DEFAULT_LOG, CONFIG_DEFAULT_MISMATCH);

    spi_connection_manager = spi_manager_initialize();

    int bridge_ret = bridge_init();

    printk(KERN_INFO "SafeHarbor: Initializing IOCTL bridge [%s]\n", bridge_ret == 0 ? "success" : "failed");

    mutex_init(&file_mutex);
    mutex_init(&rule_mutex);

    spin_lock_init(&log_lock);

    ret = configuration_load(configuration);

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