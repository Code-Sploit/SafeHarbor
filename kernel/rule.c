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
#include "../include/dpi.h"

#define FILE_PATH "/etc/safeharbor.conf"

void get_key(char *line, char *buf);
void get_value(char *line, char *buf);
void get_key_value(char *line, char *key, char *value);
void get_keyword_by_index(char *line, char *buf, int index);

struct Rule *make_rule(char *name, char *line);

void get_key(char *line, char *buf) {
    int i = 0;
    while (line[i] != ' ') {
        buf[i] = line[i];
        i++;
    }
}

void get_value(char *line, char *buf) {
    int i = 0;
    while (line[i] != '=' && line[i] != '\0') {
        i++;
    }
    i += 2;
    int j = 0;
    while (line[i] != ';' && line[i] != '\0') {
        buf[j] = line[i];
        i++;
        j++;
    }
    buf[j] = '\0';
}

void get_keyword_by_index(char *line, char *buf, int index)
{
    int i = 0;
    int j = 0;
    int k = 0;

    for (j = 0; j < index; j++)
    {
        while (line[i] != ' ' && line[i] != '\0')
        {
            i++;
        }
    }

    j = i + 1;

    while (line[j] != ' ' && line[j] != '\0')
    {
        buf[k] = line[j];

        k++;
        j++;
    }
}

void get_key_value(char *line, char *key, char *value) {
    get_key(line, key);
    get_value(line, value);
}

struct Rule *make_rule(char *name, char *line) {

    struct Rule *rule = NULL;

    char *action;
    char *proto;
    char *direction;
    char *src_ip;
    char *src_port;
    char *dest_ip;
    char *dest_port;

    action = strsep(&line, " ");
    if (!action) {
        return rule;
    }
    proto = strsep(&line, " ");
    if (!proto) {
        return rule;
    }
    direction = strsep(&line, " ");
    if (!direction) {
        return rule;
    }
    src_ip = strsep(&line, " ");
    src_ip = strsep(&line, " ");
    if (!src_ip) {
        return rule;
    }
    src_port = strsep(&line, " ");
    src_port = strsep(&line, " ");
    if (!src_port) {
        return rule;
    }
    dest_ip = strsep(&line, " ");
    dest_ip = strsep(&line, " ");
    if (!dest_ip) {
        return rule;
    }
    dest_port = strsep(&line, " ");
    dest_port = strsep(&line, " ");
    if (!dest_port) {
        return rule;
    }

    dest_port[strlen(dest_port) - 1] = '\0';

    rule = rule_initialize((strcmp(action, "deny") == 0) ? 1 : 0, direction, proto, src_ip, src_port, dest_ip, dest_port, name);

    return rule;
}

struct Configuration *configuration_initialize(int filtering, int logging, int mismatches)
{
    struct Configuration *configuration = kmalloc(sizeof(struct Configuration), GFP_KERNEL);

    if (!configuration)
    {
        printk(KERN_INFO "SafeHarbor: Failed to allocate configuration\n");

        return NULL;
    }

    configuration->filtering = filtering;
    configuration->logging = logging;
    configuration->mismatches = mismatches;

    configuration->rule_count = 0;
    configuration->group_count = 0;

    configuration->rules = kmalloc(sizeof(struct Rule *), GFP_KERNEL);
    configuration->groups = kmalloc(sizeof(struct Group *), GFP_KERNEL);

    return configuration;
}

struct Rule *rule_initialize(int action, char *direction, char *protocol, char *src, char *sport, char *dst, char *dport, char *name)
{
    struct Rule *rule = kmalloc(sizeof(struct Rule), GFP_KERNEL);

    if (!rule)
    {
        printk(KERN_INFO "SafeHarbor: Failed to allocate rule\n");

        return NULL;
    }

    rule->action = action;
    
    rule->direction = kstrdup(direction, GFP_KERNEL);
    rule->protocol = kstrdup(protocol, GFP_KERNEL);
    rule->src = kstrdup(src, GFP_KERNEL);
    rule->sport = kstrdup(sport, GFP_KERNEL);
    rule->dst = kstrdup(dst, GFP_KERNEL);
    rule->dport = kstrdup(dport, GFP_KERNEL);
    rule->name = kstrdup(name, GFP_KERNEL);

    return rule;
}

struct Group *group_initialize(char *name, int logging, int filtering)
{
    struct Group *group = kmalloc(sizeof(struct Group), GFP_KERNEL);

    if (!group)
    {
        printk(KERN_INFO "SafeHarbor: Failed to allocate group\n");

        return NULL;
    }

    group->name = kstrdup(name, GFP_KERNEL);

    group->logging = logging;
    group->filtering = filtering;

    group->rules = kmalloc(sizeof(struct Rule *), GFP_KERNEL);

    return group;
}

void configuration_add_rule(struct Configuration *configuration, struct Rule *rule)
{
    if (!configuration || !rule)
    {
        return;
    }

    configuration->rule_count++;

    configuration->rules = krealloc(configuration->rules, configuration->rule_count * sizeof(struct Rule *), GFP_KERNEL);

    configuration->rules[configuration->rule_count - 1] = rule;
}

void configuration_add_group(struct Configuration *configuration, struct Group *group)
{
    if (!configuration || !group)
    {
        return;
    }

    configuration->group_count++;

    configuration->groups = krealloc(configuration->groups, configuration->group_count * sizeof(struct Group *), GFP_KERNEL);

    configuration->groups[configuration->group_count - 1] = group;
}

void configuration_add_rule_to_group(struct Group *group, struct Rule *rule)
{
    if (!group || !rule)
    {
        return;
    }

    group->rule_count++;

    group->rules = krealloc(group->rules, group->rule_count * sizeof(struct Rule *), GFP_KERNEL);

    group->rules[group->rule_count - 1] = rule;
}

void group_set_rules(struct Group *group, struct Rule **rules, int rule_count)
{
    if (!group || !rules || rule_count == 0)
    {
        return;
    }

    for (int i = 0; i < rule_count; i++)
    {
        configuration_add_rule_to_group(group, rules[i]);
    }
}

int configuration_load(struct Configuration *configuration)
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
        
        int parsing_rules_in_group = 0;
        int settings_parsing = 0;
        int group_parsing = 0;
        int parsing_group = 0;
        int protocol_parsing = 0;
        int dpi_parsing = 0;
        int rule_parsing = 0;
        int parsing = 0;
        int group_found = 0;
        
        char current_group[64];
        
        while ((line = strsep(&ptr, "\n")) != NULL)
        {
            remove_whitespaces(line);
            
            if (parsing == 0)
            {
                if (line[0] == '[')
                {
                    char identifier[64];
                 
                    int i = 1;
                 
                    while (line[i] != ']')
                    {
                        identifier[i - 1] = line[i];
                        i++;
                    }

                    identifier[i - 1] = '\0';
                    
                    if (strcmp(identifier, "GlobalSettings") == 0)
                    {
                        settings_parsing = 1;
                        parsing = 1;
                    }
                    else if (strcmp(identifier, "RuleGroups") == 0)
                    {
                        group_parsing = 1;
                        parsing = 1;
                    }
                    else if (strcmp(identifier, "IndividualRules") == 0)
                    {
                        rule_parsing = 1;
                        parsing = 1;
                    }
                    else if (strcmp(identifier, "ProtocolRegistration") == 0)
                    {
                        protocol_parsing = 1;
                        parsing = 1;
                    }
                    else if (strcmp(identifier, "DPISettings") == 0)
                    {
                        dpi_parsing = 1;
                        parsing = 1;
                    }
                }
            }
            else
            {
                if (settings_parsing == 1)
                {
                    if (line[0] == '[') 
                    {
                        settings_parsing = 0;
                        parsing = 0;
                     
                        continue;
                    }

                    char key[64];
                    char value[64];
                    
                    get_key_value(line, key, value);
                    
                    if (strcmp(key, "filtering") == 0)
                    {
                        configuration->filtering = (strcmp(value, "on") == 0) ? 1 : 0;
                    }
                    else if (strcmp(key, "logging") == 0)
                    {
                        configuration->logging = (strcmp(value, "on") == 0) ? 1 : 0;
                    }
                    else if (strcmp(key, "mismatches") == 0)
                    {
                        configuration->mismatches = (strcmp(value, "on") == 0) ? 1 : 0;
                    }
                    else if (strcmp(key, "spi") == 0)
                    {
                        configuration->spi = (strcmp(value, "on") == 0) ? 1 : 0;
                    }
                    else if (strcmp(key, "dpi") == 0)
                    {
                        configuration->dpi = (strcmp(value, "on") == 0) ? 1 : 0;
                    }
                    else
                    {
                        printk(KERN_ERR "SafeHarbor: Invalid configuration setting: [%s]\n", key);
                    }
                }
                else if (protocol_parsing == 1)
                {
                    if (line[0] == '[')
                    {
                        protocol_parsing = 0;
                        parsing = 0;

                        continue;
                    }

                    char action[64];
                    char name[64];
                    char port[8];

                    get_keyword_by_index(line, action, 0);
                    get_keyword_by_index(line, name, 2);
                    get_keyword_by_index(line, port, 5);

                    if (strcmp(action, "register") == 0)
                    {
                        /* register protocol <name> as port <port> */

                        struct DPIPortBind *port_bind = dpi_port_bind_initialize(name, atoi(port));

                        dpi_manager_add(dpi_manager, port_bind);
                    }
                }
                else if (dpi_parsing == 1)
                {
                    if (line[0] == '[')
                    {
                        dpi_parsing = 0;
                        parsing = 0;

                        continue;
                    }

                    char action[64];
                    char name[64];
                    char target[64];

                    get_keyword_by_index(line, action, 0);
                    get_keyword_by_index(line, name, 2);
                    get_keyword_by_index(line, target, 4);

                    if (strcmp(action, "ban") == 0)
                    {
                        /* ban protocol <protocol> for <ip/any> */

                        configuration->banned_protocol_count++;

                        struct BannedProtocol *banned_protocol = kmalloc(sizeof(struct BannedProtocol), GFP_KERNEL);

                        banned_protocol->name   = name;
                        banned_protocol->target = target;

                        configuration->banned_protocols = krealloc(configuration->banned_protocols, configuration->banned_protocol_count * sizeof(struct BannedProtocol *), GFP_KERNEL);

                        configuration->banned_protocols[configuration->banned_protocol_count - 1] = banned_protocol;
                    }
                }
                else if (group_parsing == 1)
                {
                    if (parsing_group == 0)
                    {
                        if (line[0] == '[' && line[1] != '/')
                        {
                            int i = 1;
                            int j = 0;
                         
                            while (line[i] != ']' && line[i] != '\0')
                            {
                                current_group[j] = line[i];
                             
                                i++;
                                j++;
                            }

                            current_group[j] = '\0';
                            
                            group_found = 1;
                            parsing_group = 1;
                            
                            // Initialize the group and allocate memory for it
                            struct Group *group = group_initialize(current_group, 0, 0);
                            
                            if (!group)
                            {
                                ret = -ENOMEM;  // Memory allocation error
                             
                                goto out;
                            }
                            
                            configuration_add_group(configuration, group);
                        }
                        else if (line[0] == '[' && line[1] == '/')
                        {

                            parsing_group = 0;
                            parsing = 0;

                            continue;
                        }
                    }
                    else
                    {
                        if (line[0] == '[' && line[1] == '/')
                        {
                            parsing_group = 0;
                            group_found = 0;
                         
                            current_group[0] = '\0'; // Reset current_group
                        }
                        else
                        {
                            if (group_found)
                            {
                                if (parsing_rules_in_group == 0)
                                {
                                    char key[64];
                                    char value[64];
                                 
                                    get_key(line, key);
                                 
                                    if (strcmp(key, "rules") == 0)
                                    {
                                        parsing_rules_in_group = 1;
                                    }
                                    else
                                    {
                                        get_value(line, value);
                                     
                                        if (strcmp(key, "logging") == 0)
                                        {
                                            configuration->groups[configuration->group_count - 1]->logging = (strcmp(value, "on") == 0) ? 1 : 0;
                                        }
                                        else if (strcmp(key, "filtering") == 0)
                                        {
                                            configuration->groups[configuration->group_count - 1]->filtering = (strcmp(value, "on") == 0) ? 1 : 0;
                                        }
                                        else
                                        {
                                            printk(KERN_ERR "SafeHarbor: Invalid keyword [%s] in group [%s]\n", key, current_group);
                                        }
                                    }
                                }
                                else
                                {
                                    if (line[0] == '}')
                                    {
                                        parsing_rules_in_group = 0;
                                    }
                                    else
                                    {
                                        remove_whitespaces(line);
                                     
                                        struct Rule *rule = make_rule(current_group, line);
                                     
                                        if (!rule) {
                                            ret = -ENOMEM;  // Memory allocation error
                                     
                                            goto out;
                                        }
                                     
                                        configuration_add_rule_to_group(configuration->groups[configuration->group_count - 1], rule);
                                    }
                                }
                            }
                        }
                    }
                }
                else if (rule_parsing == 1)
                {
                    if (line[0] == '[')
                    {
                        rule_parsing = 0;
                        parsing = 0;
                    }
                    else
                    {
                        char key[64];
                        char value[64];
                     
                        get_key_value(line, key, value);
                     
                        struct Rule *rule = make_rule(key, value);
                     
                        if (!rule)
                        {
                            ret = -ENOMEM;  // Memory allocation error
                     
                            goto out;
                        }
                     
                        configuration_add_rule(configuration, rule);
                    }
                }
            }
        }
    }
    
out:
    filp_close(file, NULL);
    mutex_unlock(&file_mutex);

    return ret;
}

int configuration_reset(struct Configuration *configuration)
{
    memset(configuration, 0, sizeof(struct Configuration));
 
    return 0;
}
