#pragma once
#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

pkt_result pass_up_to_layer(struct nw_layer *self, char *up_name, struct pkt *packet);

#ifdef __cplusplus
}
#endif
