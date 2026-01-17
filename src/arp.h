#pragma once
#include "types.h"

struct arp_context
{
    unsigned char ipv4_address[4];
    unsigned char mac_address[6];
    struct arp_table *arp_table_head;
};

struct arp_table
{
    unsigned char ipv4_address[4];
    unsigned char mac_address[6];
    struct arp_table *next;
};

int receive_arp_up(struct nw_layer *self, const struct pkt *data);
int send_arp_down(struct nw_layer *self, const struct pkt *data);