#pragma once
#include "layer_router.h"
#include "types.h"

#define TCP_LISTNR_HTBL_SIZE 128
#define TCP_CONN_HTBL_SIZE 1024

#ifdef __cplusplus
extern "C" {
#endif

pkt_result send_tcp_down(struct nw_layer_t *self, struct pkt_t *packet);
pkt_result receive_tcp_up(struct nw_layer_t *self, struct pkt_t *packet);

#ifdef __cplusplus
}
#endif
