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
#include "../include/filter.h"

int filter_match_protocol(int protocol, char *rule_protocol)
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

int filter_match_direction(int direction, char *rule_direction)
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

int filter_match_ip(unsigned int ip, char *rule_ip)
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

int filter_match_port(unsigned int port, char *rule_port)
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

unsigned int filter(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    if (configuration->filtering == 0)
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

    char *rule_active = kmalloc(64, GFP_KERNEL);
    char *group_active = kmalloc(64, GFP_KERNEL);

    int rule_in_group_active = 0;
    int log_in_group = 1;

    /* Parse rules first */

    for (int i = 0; i < configuration->rule_count; i++)
    {
        struct Rule *rule = configuration->rules[i];

        if (rule->action == 0)
        {
            /* It's an allow filter so no filtering required */

            continue;
        }
        else
        {
            if (filter_match_protocol(protocol, rule->protocol) == FILTER_MATCH &&
                filter_match_direction(direction, rule->direction) == FILTER_MATCH &&
                filter_match_ip(src_ip, rule->src) == FILTER_MATCH &&
                filter_match_ip(dest_ip, rule->dst) == FILTER_MATCH &&
                filter_match_port(src_port, rule->sport) == FILTER_MATCH &&
                filter_match_port(dest_port, rule->dport) == 1)
            {
                drop = 1;
                rule_in_group_active = -1;

                rule_active = kstrdup(rule->name, GFP_KERNEL);
            }
        }
    }

    /* Parse groups next */

    for (int i = 0; i < configuration->group_count; i++)
    {
        struct Group *group = configuration->groups[i];

        if (group->filtering == 0)
        {
            continue;
        }

        if (group->logging == 0)
        {
            log_in_group = 0;
        }

        for (int j = 0; j < group->rule_count; j++)
        {
            struct Rule *rule = group->rules[j];

            if (rule->action == 0)
            {
                /* It's an allow filter so no filtering required */

                continue;
            }
            else
            {
                if (filter_match_protocol(protocol, rule->protocol) == FILTER_MATCH &&
                filter_match_direction(direction, rule->direction) == FILTER_MATCH &&
                filter_match_ip(src_ip, rule->src) == FILTER_MATCH &&
                filter_match_ip(dest_ip, rule->dst) == FILTER_MATCH &&
                filter_match_port(src_port, rule->sport) == FILTER_MATCH &&
                filter_match_port(dest_port, rule->dport) == 1)
                {
                    drop = 1;
                    rule_in_group_active = j;

                    group_active = kstrdup(group->name, GFP_KERNEL);
                }
            }
        }
    }

    if (configuration->logging != 0)
    {
        if (rule_in_group_active >= 0 && log_in_group == 1)
        {
            if (configuration->mismatches == 1)
            {
                log_message("PACKET: [%s] [%s] [%s] [%d] [%s] [%d] [%s] by group [%s] rule [%d]\n",
                        (protocol == IPPROTO_TCP) ? "tcp" : "udp",
                        (direction == 0) ? "out" : "in",
                        ip_ntoa(src_ip),
                        src_port,
                        ip_ntoa(dest_ip),
                        dest_port, (drop == 1) ? "DROPPED" : "ACCEPTED", group_active, rule_in_group_active);
            }
            else
            {
                if (drop == 1)
                {
                    log_message("PACKET: [%s] [%s] [%s] [%d] [%s] [%d] [%s] by group [%s] rule [%d]\n",
                        (protocol == IPPROTO_TCP) ? "tcp" : "udp",
                        (direction == 0) ? "out" : "in",
                        ip_ntoa(src_ip),
                        src_port,
                        ip_ntoa(dest_ip),
                        dest_port, "DROPPED", group_active, rule_in_group_active);
                }
            }
        }
        else
        {
            if (configuration->mismatches == 1)
            {
                log_message("PACKET: [%s] [%s] [%s] [%d] [%s] [%d] [%s] by rule [%s]\n",
                            (protocol == IPPROTO_TCP) ? "tcp" : "udp",
                            (direction == 0) ? "out" : "in",
                            ip_ntoa(src_ip),
                            src_port,
                            ip_ntoa(dest_ip),
                            dest_port, (drop == 1) ? "DROPPED" : "ACCEPTED", rule_active);
            }
            else
            {
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
            }
        }
    }

    return (drop == 1) ? NF_DROP : NF_ACCEPT;
}