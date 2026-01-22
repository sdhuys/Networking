#pragma once
#include <arpa/inet.h>
#include "arp.h"
#include "types.h"

pkt_result receive_ipv4_up(struct nw_layer *self, struct pkt *packet);
pkt_result send_ipv4_down(struct nw_layer *self, struct pkt *packet);
uint16_t calc_header_checksum(struct ipv4_header *header, size_t header_len);
pkt_result send_to_icmp(struct nw_layer *self, struct pkt *packet);
bool relevant_destination_ip(ipv4_address dest_ip, struct nw_layer *self);