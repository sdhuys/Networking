#pragma once
#include <arpa/inet.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "types.h"

struct ethernet_context
{
    mac_address mac;
};

struct ethernet_header
{
    mac_address dest_mac;
    mac_address src_mac;
    unsigned short ethertype;
} __attribute__((packed));


enum ether_type
{
    IPV4 = 0x0800,
    ARP = 0x0806,
    IPV6 = 0x86DD,
    VLAN = 0x8100
};

int receive_frame_up(struct nw_layer *self, const struct pkt *data);
int send_frame_down(struct nw_layer *self, const struct pkt *data);
void print_incoming(const struct ethernet_header *header);
bool relevant_destination_mac(const mac_address dest_mac, struct nw_layer *self);