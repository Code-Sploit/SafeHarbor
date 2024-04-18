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