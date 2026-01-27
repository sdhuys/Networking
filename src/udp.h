#pragma once
#include "checksum.h"
#include "layer_router.h"
#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

pkt_result send_udp_down(struct nw_layer_t *self, struct pkt_t *packet);
pkt_result receive_udp_up(struct nw_layer_t *self, struct pkt_t *packet);
bool validate_checksum(struct udp_header_t *header, struct pkt_t *packet);

#ifdef __cplusplus
}
#endif
