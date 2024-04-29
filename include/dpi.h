#ifndef DPI_H
#define DPI_H

struct DPIPacket
{
    void *priv;

    struct sk_buff *skb;

    const struct nf_hook_state *state;

    unsigned int sip;
    unsigned int dip;
    unsigned int sport;
    unsigned int dport;
    unsigned int header_protocol;
    unsigned int protocol;

    unsigned int has_correct_header_length;

    unsigned int should_drop;

    char *protocol_name;
};

struct DPIPortBind
{
    char *name;

    unsigned int port;
};

struct DPIManager
{
    struct DPIPortBind **binds;

    int bind_count;
};

struct DPIManager *dpi_manager_initialize(void);

struct DPIPortBind *dpi_port_bind_initialize(char *name, unsigned int port);

struct DPIPacket *dpi_packet_initialize(void *priv, struct sk_buff *skb, const struct nf_hook_state *state,
                                        unsigned int sip, unsigned int dip,
                                        unsigned int sport, unsigned int dport,
                                        unsigned int protocol);

void dpi_analyze_header_length(struct DPIPacket *packet);
void dpi_analyze_protocol(struct DPIPacket *packet);
void dpi_analyze_buffer(struct DPIPacket *packet);

unsigned int dpi_analyze(struct DPIPacket *packet);

void dpi_manager_add(struct DPIManager *manager, struct DPIPortBind *port_bind);

void dpi_packet_destroy(struct DPIPacket *packet);

#endif