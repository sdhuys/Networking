#pragma once
#include <stddef.h>

#define MAC_ADDR_LEN 6
#define IPV4_BROADCAST_MAC (unsigned char[MAC_ADDR_LEN]){0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}

typedef unsigned char mac_address[MAC_ADDR_LEN];

struct pkt_metadata
{
    mac_address src_mac;
};

struct pkt
{
    const unsigned char *data;
    const size_t len;
    size_t offset;
    struct pkt_metadata metadata;
};

struct nw_layer
{
    char *name;
    int (*send_down)(struct nw_layer *self, const struct pkt *packet);
    int (*rcv_up)(struct nw_layer *self, const struct pkt *packet);
    struct nw_layer **ups;
    struct nw_layer **downs;
    size_t ups_count;
    size_t downs_count;
    void *context;
};