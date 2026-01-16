#pragma once
#include <arpa/inet.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include "layer.h"

#define DUMMY_MAC (unsigned char[6]){0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
#define IPV4_BROADCAST_MAC (unsigned char[6]){0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}

typedef unsigned char mac_address[6];

struct ethernet_header
{
    mac_address dest_mac;
    mac_address src_mac;
    unsigned short ethertype;
} __attribute__((packed));

struct ethernet_frame
{
    struct ethernet_header header;
    unsigned char payload[1500];
    unsigned char frame_check_sequence[4];
} __attribute__((packed));

enum ether_type
{
    IPV4 = 0x0800,
    ARP = 0x0806,
    IPV6 = 0x86DD,
    VLAN = 0x8100
};

int read_frame(struct nw_layer *self, struct nw_layer_data *data);
int create_frame(struct nw_layer *self, struct nw_layer_data *data);
void print_incoming(const struct ethernet_header *header);
bool relevant_destination_mac(const mac_address dest_mac);