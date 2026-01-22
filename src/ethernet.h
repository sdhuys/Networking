#pragma once
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "types.h"

pkt_result receive_frame_up(struct nw_layer *self, struct pkt *packet);
pkt_result send_frame_down(struct nw_layer *self, struct pkt *packet);
void print_incoming(struct ethernet_header *header);
void print_outgoing(struct ethernet_header *header);
bool relevant_destination_mac(mac_address dest_mac, struct nw_layer *self);
pkt_result send_to_arp(struct nw_layer *self, struct pkt *packet);
pkt_result send_to_ipv4(struct nw_layer *self, struct pkt *packet);