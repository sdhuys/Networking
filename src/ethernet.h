#pragma once
#include "layer_router.h"
#include "types.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

pkt_result receive_frame_up(struct nw_layer_t *self, struct pkt_t *packet);
pkt_result send_frame_down(struct nw_layer_t *self, struct pkt_t *packet);
void print_incoming(struct ethernet_header_t *header);
void print_outgoing(struct ethernet_header_t *header);
bool relevant_destination_mac(mac_address dest_mac, struct nw_layer_t *self);
pkt_result send_to_arp(struct nw_layer_t *self, struct pkt_t *packet);
pkt_result send_to_ipv4(struct nw_layer_t *self, struct pkt_t *packet);

#ifdef __cplusplus
}
#endif
