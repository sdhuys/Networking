#pragma once
#include "arp.h"
#include "checksum.h"
#include "layer_router.h"
#include "types.h"
#include <arpa/inet.h>

#ifdef __cplusplus
extern "C" {
#endif

pkt_result receive_ipv4_up(struct nw_layer_t *self, struct pkt_t *packet);
pkt_result send_ipv4_down(struct nw_layer_t *self, struct pkt_t *packet);
bool relevant_destination_ip(ipv4_address dest_ip, struct nw_layer_t *self);
void get_route(struct nw_layer_t *self, ipv4_address dest_ip, struct route_t **route_out);
void write_ipv4_header(struct ipv4_context_t *context,
		       struct ipv4_header_t *header,
		       struct pkt_t *packet);

#ifdef __cplusplus
}
#endif
