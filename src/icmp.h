#pragma once
#include "checksum.h"
#include "layer_router.h"
#include "types.h"
#include <arpa/inet.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

pkt_result send_icmp_down(struct nw_layer *self, struct pkt *packet);
pkt_result receive_icmp_up(struct nw_layer *self, struct pkt *packet);
void echo_request_to_reply(struct pkt *packet, struct icmp_header *header);

#ifdef __cplusplus
}
#endif
