#pragma once
#include "checksum.h"
#include "layer_router.h"
#include "types.h"
#include "udp_hashtable.h"
#include "udp_socket.h"
#include <arpa/inet.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

pkt_result send_udp_down(struct nw_layer_t *self, struct pkt_t *packet);
pkt_result receive_udp_up(struct nw_layer_t *self, struct pkt_t *packet);
uint16_t compute_checksum_internal(struct udp_header_t *header, struct pkt_t *packet);
#ifdef __cplusplus
}
#endif
