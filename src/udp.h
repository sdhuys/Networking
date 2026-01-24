#pragma once
#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

pkt_result send_udp_down(struct nw_layer *self, struct pkt *packet);
pkt_result receive_udp_up(struct nw_layer *self, struct pkt *packet);

#ifdef __cplusplus
}
#endif
