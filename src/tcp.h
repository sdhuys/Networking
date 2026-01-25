#pragma once
#include "layer_router.h"
#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

pkt_result send_tcp_down(struct nw_layer *self, struct pkt *packet);
pkt_result receive_tcp_up(struct nw_layer *self, struct pkt *packet);

#ifdef __cplusplus
}
#endif
