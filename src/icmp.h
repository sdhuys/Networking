#pragma once
#include "layer_router.h"
#include "types.h"
#include <arpa/inet.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

pkt_result send_icmp_down(struct nw_layer_t *self, struct pkt_t *packet);
pkt_result receive_icmp_up(struct nw_layer_t *self, struct pkt_t *packet);
uint16_t calc_packet_checksum(void *data, size_t len);
void echo_request_to_reply(struct pkt_t *packet, struct icmp_header_t *header, size_t len);

#ifdef __cplusplus
}
#endif
