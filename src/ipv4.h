#pragma once
#include "arp.h"
#include "types.h"
#include <arpa/inet.h>

#ifdef __cplusplus
extern "C" {
#endif

pkt_result receive_ipv4_up(struct nw_layer *self, struct pkt *packet);
pkt_result send_ipv4_down(struct nw_layer *self, struct pkt *packet);
uint16_t calc_header_checksum(struct ipv4_header *header, size_t header_len);
pkt_result send_to_icmp(struct nw_layer *self, struct pkt *packet);
bool relevant_destination_ip(ipv4_address dest_ip, struct nw_layer *self);
void get_next_hop(struct nw_layer *self, struct ipv4_header *header, ipv4_address *out_next_hop);
#ifdef __cplusplus
}
#endif
