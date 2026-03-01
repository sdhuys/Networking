#pragma once
#include "arp.h"
#include "checksum.h"
#include "layer_router.h"
#include "routing_table.h"
#include "types.h"
#include <arpa/inet.h>

#ifdef __cplusplus
extern "C" {
#endif

pkt_result receive_ipv4_up(struct nw_layer *self, struct pkt *packet);
pkt_result send_ipv4_down(struct nw_layer *self, struct pkt *packet);
bool relevant_destination_ip(ipv4_address_t dest_ip, struct nw_layer *self);
void write_ipv4_header(struct ipv4_header *header, struct pkt *packet);

#ifdef __cplusplus
}
#endif
