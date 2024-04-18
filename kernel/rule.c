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
#include "../include/helper.h"
#include "../include/rule.h"

#define FILE_PATH "/etc/safeharbor.conf"

int config_load(void)
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
            
            remove_whitespaces(line);

            if (line[0] == '#')
            {
                continue;
            }
            else if (line[0] == '\n')
            {
                continue;
            }

            ret = parse_line(line);

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

int parse_line(char *line)
{
    char *buffer = kmalloc(1024, GFP_KERNEL);

    strcpy(buffer, line);
    
    char *keyword = strsep(&buffer, " ");

    if (strcmp(keyword, "filter") == 0)
    {
        char *arg = strsep(&buffer, " ");

        if (arg != NULL)
        {
            if (strcmp(arg, "on") == 0)
            {
                DO_FILTERING = 1;
            }
            else if (strcmp(arg, "off") == 0)
            {
                DO_FILTERING = 0;
            }
            else
            {
                printk(KERN_INFO "SafeHarbor: Invalid value for setting DO_FILTERING\n");
                return -1;
            }
        }
        else
        {
            printk(KERN_INFO "SafeHarbor: Missing argument for setting DO_FILTERING\n");
            return -1;
        }
    }
    else if (strcmp(keyword, "mismatch") == 0)
    {
        char *arg = strsep(&buffer, " ");

        if (arg != NULL)
        {
            if (strcmp(arg, "on") == 0)
            {
                DO_SHOW_RULE_MISMATCHES = 1;
            }
            else if (strcmp(arg, "off") == 0)
            {
                DO_SHOW_RULE_MISMATCHES = 0;
            }
            else
            {
                printk(KERN_INFO "SafeHarbor: Invalid value for setting DO_SHOW_RULE_MISMATCHES\n");
                return -1;
            }
        }
        else
        {
            printk(KERN_INFO "SafeHarbor: Missing argument for setting DO_SHOW_RULE_MISMATCHES\n");
            return -1;
        }
    }
    else if (strcmp(keyword, "logging") == 0)
    {
        char *arg = strsep(&buffer, " ");

        if (arg != NULL) 
        {
            if (strcmp(arg, "on") == 0)
            {
                DO_LOGGING = 1;
            }
            else if (strcmp(arg, "off") == 0)
            {
                DO_LOGGING = 0;
            }
            else
            {
                printk(KERN_INFO "SafeHarbor: Invalid value for setting DO_LOGGING\n");
                return -1;
            }
        }
        else
        {
            printk(KERN_INFO "SafeHarbor: Missing argument for setting DO_LOGGING\n");
            return -1;
        }
    }
    else
    {
        parse_rule(line);
    }

    return 0;
}

int parse_rule(char *rule)
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