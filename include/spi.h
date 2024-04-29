#ifndef SPI_H
#define SPI_H

enum SPIConnectionState
{
    SPI_CONN_STATE_NONE,
    SPI_CONN_STATE_ACTIVE,
    SPI_CONN_STATE_SLEEPING,
    SPI_CONN_STATE_BLOCKED
};

struct SPIConnection
{
    unsigned int sip;
    unsigned int dip;

    unsigned int sport;
    unsigned int dport;

    unsigned int state;
};

struct SPIConnectionManager
{
    struct SPIConnection **connections;

    int connection_count;
};

struct SPIConnectionManager *spi_manager_initialize(void);
struct SPIConnection *spi_connection_initialize(unsigned int sip, unsigned int dip, unsigned int sport, unsigned int dport, unsigned int state);

int spi_connection_find(struct SPIConnectionManager *connection_manager, struct SPIConnection *connection);

void spi_connection_add(struct SPIConnectionManager *connection_manager, struct SPIConnection *connection);
void spi_connection_del(struct SPIConnectionManager *connection_manager, struct SPIConnection *connection);

void spi_manager_destroy(struct SPIConnectionManager *connection_manager);
void spi_connection_destroy(struct SPIConnection *connection);

unsigned int spi_check(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);

#endif