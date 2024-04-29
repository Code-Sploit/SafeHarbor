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
#include "../include/spi.h"

struct SPIConnectionManager *spi_manager_initialize()
{
    struct SPIConnectionManager *connection_manager = kmalloc(sizeof(struct SPIConnectionManager), GFP_KERNEL);

    if (!connection_manager)
    {
        return NULL;
    }

    connection_manager->connections = kmalloc(sizeof(struct SPIConnection *), GFP_KERNEL);

    connection_manager->connection_count = 0;

    return connection_manager;   
}

struct SPIConnection *spi_connection_initialize(unsigned int sip, unsigned int dip, unsigned int sport, unsigned int dport, unsigned int state)
{
    struct SPIConnection *connection = kmalloc(sizeof(struct SPIConnection), GFP_KERNEL);

    if (!connection)
    {
        return NULL;
    }

    connection->sip = sip;
    connection->dip = dip;
    
    connection->sport = sport;
    connection->dport = dport;

    connection->state = state;

    return connection;
}

int spi_connection_find(struct SPIConnectionManager *connection_manager, struct SPIConnection *connection)
{
    if (!connection_manager || !connection)
    {
        return -1;
    }

    for (int i = 0; i < connection_manager->connection_count; i++)
    {
        struct SPIConnection *connection_iterator = connection_manager->connections[i];

        if (!connection_iterator)
        {
            return -1;
        }

        if (connection_iterator == connection)
        {
            return i;
        }
    }

    return -1;
}

void spi_connection_add(struct SPIConnectionManager *connection_manager, struct SPIConnection *connection)
{
    if (!connection_manager || !connection)
    {
        return;
    }

    connection_manager->connection_count++;

    connection_manager->connections = krealloc(connection_manager->connections, connection_manager->connection_count * sizeof(struct SPIConnection *), GFP_KERNEL);

    connection_manager->connections[connection_manager->connection_count - 1] = connection;
}

void spi_connection_del(struct SPIConnectionManager *connection_manager, struct SPIConnection *connection)
{
    if (!connection_manager || !connection)
    {
        return ;
    }

    int connection_found = spi_connection_find(connection_manager, connection);

    if (connection_found < 0)
    {
        return;
    }

    spi_connection_destroy(connection_manager->connections[connection_found]);
}

void spi_manager_destroy(struct SPIConnectionManager *connection_manager)
{
    kfree(connection_manager);
}

void spi_connection_destroy(struct SPIConnection *connection)
{
    kfree(connection);
}

unsigned int spi_check(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
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

    struct SPIConnection *connection = spi_connection_initialize(src_ip, dest_ip, src_port, dest_port, SPI_CONN_STATE_NONE);

    if (!connection)
    {
        return NF_ACCEPT;
    }

    int connection_found = spi_connection_find(spi_connection_manager, connection);

    if (connection_found < 0)
    {
        connection->state = SPI_CONN_STATE_ACTIVE;

        spi_connection_add(spi_connection_manager, connection);
    }
    else
    {
        struct SPIConnection *fconnection = spi_connection_manager->connections[connection_found];

        if (!fconnection)
        {
            return NF_ACCEPT;
        }

        if (fconnection->state == SPI_CONN_STATE_BLOCKED)
        {
            return NF_DROP;
        }
        else if (fconnection->state == SPI_CONN_STATE_ACTIVE)
        {
            return NF_ACCEPT;
        }
        else if (fconnection->state == SPI_CONN_STATE_SLEEPING)
        {
            spi_connection_manager->connections[connection_found]->state = SPI_CONN_STATE_ACTIVE;

            return NF_ACCEPT;
        }
        else if (fconnection->state == SPI_CONN_STATE_NONE)
        {
            spi_connection_manager->connections[connection_found]->state = SPI_CONN_STATE_ACTIVE;
        }
    }

    return (drop == 1) ? NF_DROP : NF_ACCEPT;
}