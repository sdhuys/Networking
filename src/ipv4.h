#pragma once
#include "arp.h"
#include "layer_router.h"
#include "types.h"
#include <arpa/inet.h>

#ifdef __cplusplus
extern "C" {
#endif

pkt_result receive_ipv4_up(struct nw_layer *self, struct pkt *packet);
pkt_result send_ipv4_down(struct nw_layer *self, struct pkt *packet);
uint16_t calc_header_checksum(struct ipv4_header *header, size_t header_len);
bool relevant_destination_ip(ipv4_address dest_ip, struct nw_layer *self);
void get_route(struct nw_layer *self, ipv4_address dest_ip, struct route **route_out);
void write_ipv4_header(struct ipv4_context *context,
		       struct ipv4_header *header,
		       struct pkt *packet);

#ifdef __cplusplus
}
#endif
