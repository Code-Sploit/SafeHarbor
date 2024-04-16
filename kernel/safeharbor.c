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

#include "../include/safeharbor.h"

#define LOG_FILE_PATH "/var/log/safeharbor.log"
#define FILE_PATH "/etc/safeharbor.conf"

#define TIME_BUF_SIZE 32

#define MAX_BUF_SIZE 1024
#define MAX_RULES 50

#define LOG_BUF_SIZE 1024

#define BRIDGE_MAJOR 64
#define BRIDGE_MINOR 0

#define FILTER_MATCH   1
#define FILTER_NOMATCH 0

#define NIPQUAD(addr) \
    ((unsigned char *)&addr)[0], \
    ((unsigned char *)&addr)[1], \
    ((unsigned char *)&addr)[2], \
    ((unsigned char *)&addr)[3]

static int DO_SHOW_RULE_MISMATCHES = 0;
static int DO_FILTERING = 1;
static int DO_LOGGING = 1;

struct Rule {
    char action[10];
    char protocol[5];
    char direction[10];
    char src_ip[16];
    char src_port[6];
    char dest_ip[16];
    char dest_port[6];
};

static struct tm current_time_value;
static struct Rule rules[MAX_RULES];
static char log_buf[LOG_BUF_SIZE];
static struct mutex file_mutex;
static struct mutex rule_mutex;
static struct timespec64 tv;

static spinlock_t log_lock;

static int num_rules = 0;

static unsigned int filter(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);

static char *get_current_time_string(void);
static char *ip_ntoa(unsigned int ip);

static int parse_rule(char *rule);
static int config_load(void);

static void log_message(const char *format, ...);

static int atoi(const char *str);

static int bridge_init(void);
static int bridge_deinit(void);

static int bridge_open(struct inode *device, struct file *instance);
static int bridge_close(struct inode *device, struct file *instance);

static void get_until_delim(char *buffer, char *str, char delim);

static long int bridge_ctl(struct file *file, unsigned cmd, unsigned long arg);

static struct file_operations bridge_options = {
    .owner          = THIS_MODULE,
    .open           = bridge_open,
    .release        = bridge_close,
    .unlocked_ioctl = bridge_ctl
};

static void get_until_delim(char *buffer, char *str, char delim)
{
    int i = 0;

    while (str[i] != delim)
    {
        buffer[i] = str[i];

        i++;
    }

    buffer[i] = '\0';
}

static int filter_match_protocol(int protocol, char *rule_protocol);
static int filter_match_direction(int direction, char *rule_direction);
static int filter_match_ip(unsigned int ip, char *rule_ip);
static int filter_match_port(unsigned int port, char *rule_port);

static int filter_match_protocol(int protocol, char *rule_protocol)
{
    if (strcmp(rule_protocol, "tcp") == 0)
    {
        if (protocol == IPPROTO_TCP)
        {
            return FILTER_MATCH;
        }
    }
    else if (strcmp(rule_protocol, "udp") == 0)
    {
        if (protocol == IPPROTO_UDP)
        {
            return FILTER_MATCH;
        }
    }
    else if (strcmp(rule_protocol, "any") == 0)
    {
        return FILTER_MATCH;
    }

    return FILTER_NOMATCH;
}

static int filter_match_direction(int direction, char *rule_direction)
{
    if (strcmp(rule_direction, "in") == 0)
    {
        if (direction == 1)
        {
            return FILTER_MATCH;
        }
    }
    else if (strcmp(rule_direction, "out") == 0)
    {
        if (direction == 0)
        {
            return FILTER_MATCH;
        }
    }
    else if (strcmp(rule_direction, "any") == 0)
    {
        return FILTER_MATCH;
    }

    return FILTER_NOMATCH;
}

static int filter_match_ip(unsigned int ip, char *rule_ip)
{
    if (strcmp(rule_ip, ip_ntoa(ip)) == 0)
    {
        return FILTER_MATCH;
    }
    else if (strcmp(rule_ip, "any") == 0)
    {
        return FILTER_MATCH;
    }

    return FILTER_NOMATCH;
}

static int filter_match_port(unsigned int port, char *rule_port)
{
    char port_str[6];

    snprintf(port_str, sizeof(port_str), "%u", port);

    if (strcmp(rule_port, port_str) == 0)
    {
        return FILTER_MATCH;
    }
    else if (strcmp(rule_port, "any") == 0)
    {
        return FILTER_MATCH;
    }

    return FILTER_NOMATCH;
}

static int bridge_init()
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

static int bridge_deinit()
{
    unregister_chrdev(BRIDGE_MAJOR, "safeharbor");

    return 0;
}

static int bridge_open(struct inode *device, struct file *instance)
{
    /* Callback function when the device is opened */

    printk(KERN_INFO "SafeHarbor: IOCTL bridge_open() was called\n");

    return 0;
}

static int bridge_close(struct inode *device, struct file *instance)
{
    /* Callback function when the device is closed */

    printk(KERN_INFO "SafeHarbor: IOCTL bridge_close() was called\n");

    return 0;
}

static int atoi(const char *str)
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

static long int bridge_ctl(struct file *file, unsigned int cmd, unsigned long arg)
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

        default:
            kfree(arg_str); // Free allocated memory

            return -EINVAL; // Invalid argument
    }

    kfree(arg_str); // Free allocated memory

    return exit;
}

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

static struct nf_hook_ops nf_ops[] = {
    {.hook = filter, .pf = NFPROTO_IPV4, .hooknum = NF_INET_PRE_ROUTING,  .priority = NF_IP_PRI_FIRST},
    {.hook = filter, .pf = NFPROTO_IPV4, .hooknum = NF_INET_LOCAL_IN,     .priority = NF_IP_PRI_FIRST},
    {.hook = filter, .pf = NFPROTO_IPV4, .hooknum = NF_INET_FORWARD,      .priority = NF_IP_PRI_FIRST},
    {.hook = filter, .pf = NFPROTO_IPV4, .hooknum = NF_INET_LOCAL_OUT,    .priority = NF_IP_PRI_FIRST},
    {.hook = filter, .pf = NFPROTO_IPV4, .hooknum = NF_INET_POST_ROUTING, .priority = NF_IP_PRI_FIRST},
};

void log_message(const char *format, ...)
{
    if (DO_LOGGING == 0)
    {
        return;
    }

    va_list args;

    struct file *file;
    loff_t pos;
    int ret;

    va_start(args, format);
    vsnprintf(log_buf, LOG_BUF_SIZE, format, args);
    va_end(args);

    mutex_lock(&file_mutex);

    file = filp_open(LOG_FILE_PATH, O_WRONLY | O_CREAT | O_APPEND, 0777);
    
    if (IS_ERR(file))
    {
        printk(KERN_ERR "SafeHarbor: Failed to open log file: %ld\n", PTR_ERR(file));
        mutex_unlock(&file_mutex);
        return;
    }

    pos = file->f_pos;

    static char datetime[256];
    
    sprintf(datetime, "[%s] ", get_current_time_string());
    
    ret = kernel_write(file, datetime, strlen(datetime), &pos);
    
    if (ret < 0)
    {
        printk(KERN_ERR "SafeHarbor: Failed to write datetime to log file: `%d`\n", ret);
        filp_close(file, NULL);
        mutex_unlock(&file_mutex);
        return;
    }
    
    pos = file->f_pos;

    ret = kernel_write(file, log_buf, strlen(log_buf), &pos);
    
    if (ret < 0)
    {
        printk(KERN_ERR "SafeHarbor: Failed to write log message to log file: `%d`\n", ret);
    }
    else
    {

    }

    filp_close(file, NULL);

    mutex_unlock(&file_mutex);
}

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

static int config_load(void)
{
    struct file *file;
    
    char buf[MAX_BUF_SIZE];
    char *line;

    int ret = 0;

    mutex_lock(&file_mutex);

    file = filp_open(FILE_PATH, O_RDONLY, 0777);

    if (IS_ERR(file))
    {
        printk(KERN_ERR "SafeHarbor: Failed to open config file: `%s`\n", FILE_PATH);

        mutex_unlock(&file_mutex);
        
        return PTR_ERR(file);
    }

    while (1)
    {
        int bytes_read = kernel_read(file, buf, MAX_BUF_SIZE, &file->f_pos);

        if (bytes_read < 0)
        {
            printk(KERN_ERR "SafeHarbor: Failed to read file: `%s`\n", FILE_PATH);
            ret = -EIO;
            goto out;
        }
        else if (bytes_read == 0)
        {
            break;
        }

        char *ptr = buf;

        while ((line = strsep(&ptr, "\n")) != NULL)
        {
            if (strlen(line) == 0)
            {
                continue;
            }

            ret = parse_rule(line);

            if (ret < 0)
            {
                printk(KERN_ERR "SafeHarbor: Failed to parse rule: `%s`\n", line);
                goto out;
            }
        }
    }

out:
    filp_close(file, NULL);
    mutex_unlock(&file_mutex);
    return ret;
}

static int parse_rule(char *rule)
{
    if (num_rules >= MAX_RULES)
    {
        printk(KERN_ERR "SafeHarbor: Maximum number of rules (%d) exceeded\n", MAX_RULES);
        return -ENOMEM;
    }

    mutex_lock(&rule_mutex);

    char *action;
    char *proto;
    char *direction;
    char *src_ip;
    char *src_port;
    char *dest_ip;
    char *dest_port;

    action = strsep(&rule, " ");
  
    if (!action)
    {
        mutex_unlock(&rule_mutex);
        return -EINVAL;
    }

    proto = strsep(&rule, " ");
   
    if (!proto)
    {
        mutex_unlock(&rule_mutex);
        return -EINVAL;
    }

    direction = strsep(&rule, " ");
   
    if (!direction)
    {
        mutex_unlock(&rule_mutex);
        return -EINVAL;
    }

    src_ip = strsep(&rule, " ");
    
    if (!src_ip)
    {
        mutex_unlock(&rule_mutex);
        return -EINVAL;
    }

    src_port = strsep(&rule, " ");
    
    if (!src_port)
    {
        mutex_unlock(&rule_mutex);
        return -EINVAL;
    }

    dest_ip = strsep(&rule, " ");
    
    if (!dest_ip)
    {
        mutex_unlock(&rule_mutex);
        return -EINVAL;
    }

    dest_port = strsep(&rule, " ");

    if (!dest_port)
    {
        mutex_unlock(&rule_mutex);
        return -EINVAL;
    }

    strcpy(rules[num_rules].action,     action);
    strcpy(rules[num_rules].protocol,   proto);
    strcpy(rules[num_rules].direction,  direction);
    strcpy(rules[num_rules].src_ip,     src_ip);
    strcpy(rules[num_rules].src_port,   src_port);
    strcpy(rules[num_rules].dest_ip,    dest_ip);
    strcpy(rules[num_rules].dest_port,  dest_port);

    num_rules++;

    mutex_unlock(&rule_mutex);

    return 0;
}

static unsigned int filter(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    if (DO_FILTERING == 0)
    {
        return NF_ACCEPT;
    }

    struct iphdr *ip_header;
    struct udphdr *udp_header;
    struct tcphdr *tcp_header;
    
    unsigned int src_ip;
    unsigned int dest_ip;

    u16 src_port;
    u16 dest_port;
    
    int protocol;
    int direction;

    if (state->hook == NF_INET_PRE_ROUTING || state->hook == NF_INET_LOCAL_IN)
    {
        direction = 1;
    }

    ip_header = ip_hdr(skb);
    
    src_ip    = ip_header->saddr;
    dest_ip   = ip_header->daddr;
    protocol  = ip_header->protocol;

    if (protocol == IPPROTO_UDP)
    {
        udp_header = udp_hdr(skb);

        src_port   = ntohs(udp_header->source);
        dest_port  = ntohs(udp_header->dest);
    }
    else if (protocol == IPPROTO_TCP)
    {
        tcp_header = tcp_hdr(skb);

        src_port   = ntohs(tcp_header->source);
        dest_port  = ntohs(tcp_header->dest);
    }

    int drop = 0;
    int rule_active = 0;

    for (int i = 0; i < num_rules; i++)
    {
        struct Rule rule = rules[i];

        char *rule_action    = rule.action;
        char *rule_protocol  = rule.protocol;
        char *rule_direction = rule.direction;
        char *rule_src_ip    = rule.src_ip;
        char *rule_src_port  = rule.src_port;
        char *rule_dest_ip   = rule.dest_ip;
        char *rule_dest_port = rule.dest_port;

        if (strcmp(rule_action, "allow") == 0)
        {
            if (filter_match_protocol(protocol, rule_protocol) &&
                filter_match_direction(direction, rule_direction) &&
                filter_match_ip(src_ip, rule_src_ip) &&
                filter_match_port(src_port, rule_src_port) &&
                filter_match_ip(dest_ip, rule_dest_ip) &&
                filter_match_port(dest_port, rule_dest_port))
            {              
                drop = 0;
                rule_active = i + 1;
            }
        }
        else if (strcmp(rule_action, "deny") == 0)
        {
            if (filter_match_protocol(protocol, rule_protocol) &&
                filter_match_direction(direction, rule_direction) &&
                filter_match_ip(src_ip, rule_src_ip) &&
                filter_match_port(src_port, rule_src_port) &&
                filter_match_ip(dest_ip, rule_dest_ip) &&
                filter_match_port(dest_port, rule_dest_port))
            {
                drop = 1;
                rule_active = i + 1;
            }
        }
        else
        {
            printk(KERN_INFO "Invalid rule action: `%s` rule: `%d`\n", rule_action, i);

            continue;
        }
    }

    if (drop == 1)
    {
        log_message("PACKET: [%s] [%s] [%s] [%d] [%s] [%d] [%s] by rule [%d]\n",
                    (protocol == IPPROTO_TCP) ? "tcp" : "udp",
                    (direction == 0) ? "out" : "in",
                    ip_ntoa(src_ip),
                    src_port,
                    ip_ntoa(dest_ip),
                    dest_port, "DROPPED", rule_active);
    }
    else if (drop == 0)
    {
        if (rule_active != 0)
        {
            log_message("PACKET: [%s] [%s] [%s] [%d] [%s] [%d] [%s] by rule [%d]\n",
                (protocol == IPPROTO_TCP) ? "tcp" : "udp",
                (direction == 0) ? "out" : "in",
                ip_ntoa(src_ip),
                src_port,
                ip_ntoa(dest_ip),
                dest_port, "ACCEPTED", rule_active);
        }
        else
        {
            if (DO_SHOW_RULE_MISMATCHES == 1)
            {
                log_message("PACKET: [%s] [%s] [%s] [%d] [%s] [%d] [%s] by rule mismatch\n",
                    (protocol == IPPROTO_TCP) ? "tcp" : "udp",
                    (direction == 0) ? "out" : "in",
                    ip_ntoa(src_ip),
                    src_port,
                    ip_ntoa(dest_ip),
                    dest_port, "ACCEPTED");
            }
        }
    }

    return (drop == 1) ? NF_DROP : NF_ACCEPT;
}

module_init(firewall_init);
module_exit(firewall_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Samuel 't Hart");
MODULE_DESCRIPTION("A simple NetFilter firewall module");