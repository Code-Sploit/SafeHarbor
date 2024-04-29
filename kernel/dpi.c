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
#include "../include/dpi.h"

struct DPIManager *dpi_manager_initialize()
{
    struct DPIManager *dpi_manager = kmalloc(sizeof(struct DPIManager), GFP_KERNEL);

    if (!dpi_manager)
    {
        return NULL;
    }

    dpi_manager->binds = kmalloc(sizeof(struct DPIPortBind *), GFP_KERNEL);
    
    dpi_manager->bind_count = 0;
    
    return dpi_manager;
}

struct DPIPortBind *dpi_port_bind_initialize(char *name, unsigned int port)
{
    if (!name || port <= 0)
    {
        return NULL;
    }

    struct DPIPortBind *port_bind = kmalloc(sizeof(struct DPIPortBind), GFP_KERNEL);

    if (!port_bind)
    {
        return NULL;
    }

    port_bind->name = name;
    port_bind->port = port;

    return port_bind;
}

struct DPIPacket *dpi_packet_initialize(void *priv, struct sk_buff *skb, const struct nf_hook_state *state,
                                        unsigned int sip, unsigned int dip,
                                        unsigned int sport, unsigned int dport,
                                        unsigned int protocol)
{
    struct DPIPacket *packet = kmalloc(sizeof(struct DPIPacket), GFP_KERNEL);

    if (!packet)
    {
        return NULL;
    }

    packet->priv = priv;
    packet->skb  = skb;
    packet->state = state;

    packet->sip = sip;
    packet->dip = dip;

    packet->sport = sport;
    packet->dport = dport;

    packet->protocol = protocol;

    return packet;
}

void dpi_analyze_header_length(struct DPIPacket *packet)
{
    if (!packet)
    {
        return;
    }

    struct iphdr *ip_header = ip_hdr(packet->skb);
    struct tcphdr *tcp_header = NULL;
    struct udphdr *udp_header = NULL;
    
    if (packet->header_protocol == IPPROTO_TCP)
    {
        tcp_header = tcp_hdr(packet->skb);

        if (ntohs(ip_header->tot_len) < sizeof(struct iphdr) + sizeof(struct tcphdr) ||
            ntohs(ip_header->tot_len) > sizeof(struct iphdr) + sizeof(struct tcphdr) + 40)
        {
            packet->has_correct_header_length = 0;
        }
        else
        {
            packet->has_correct_header_length = 1;
        }
    }
    else if (packet->header_protocol == IPPROTO_UDP)
    {
        udp_header = udp_hdr(packet->skb);

        if (ntohs(ip_header->tot_len) < sizeof(struct iphdr) + sizeof(struct udphdr))
        {
            packet->has_correct_header_length = 0;
        }
        else
        {
            packet->has_correct_header_length = 1;
        }
    }
    else
    {
        // Handle other protocols if needed
        packet->has_correct_header_length = 1;
    }

    if (packet->has_correct_header_length == 0)
    {
        printk(KERN_INFO "SafeHarbor: DPI Flagged header length\n");
        packet->should_drop = 1;
    }
}

void dpi_analyze_protocol(struct DPIPacket *packet)
{
    if (!packet)
    {
        return;
    }

    for (int i = 0; i < dpi_manager->bind_count; i++)
    {
        struct DPIPortBind *port_bind = dpi_manager->binds[i];

        if (!port_bind)
        {
            return;
        }

        if (port_bind->port == packet->dport)
        {
            packet->protocol_name = port_bind->name;
        }
    }

    for (int i = 0; i < configuration->banned_protocol_count; i++)
    {
        struct BannedProtocol *banned_protocol = configuration->banned_protocols[i];

        if (!banned_protocol)
        {
            return;
        }

        if (strcmp(banned_protocol->name, packet->protocol_name) == 0)
        {
            if (strcmp(ip_ntoa(packet->sip), banned_protocol->target) == 0)
            {
                printk(KERN_INFO "SafeHarbor: DPI Flagged protocol\n");

                packet->should_drop = 1;
            }
            else if (strcmp(ip_ntoa(packet->dip), banned_protocol->target) == 0)
            {
                printk(KERN_INFO "SafeHarbor: DPI Flagged protocol\n");

                packet->should_drop = 1;
            }
        }
    }
}

void dpi_analyze_buffer(struct DPIPacket *packet)
{
    /* Nothing implemented here yet */
}

unsigned int dpi_analyze(struct DPIPacket *packet)
{
    if (!packet)
    {
        return NF_ACCEPT;
    }

    dpi_analyze_header_length(packet);
    dpi_analyze_protocol(packet);
    dpi_analyze_buffer(packet);

    return (packet->should_drop == 1) ? NF_DROP : NF_ACCEPT;
}

void dpi_manager_add(struct DPIManager *manager, struct DPIPortBind *port_bind)
{
    if (!manager || !port_bind)
    {
        return;
    }

    manager->bind_count++;

    manager->binds = krealloc(manager->binds, manager->bind_count * sizeof(struct DPIPortBind *), GFP_KERNEL);

    manager->binds[manager->bind_count - 1] = port_bind;
}

void dpi_packet_destroy(struct DPIPacket *packet)
{
    kfree(packet);
}