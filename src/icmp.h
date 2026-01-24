#pragma once
#include "types.h"
#include <arpa/inet.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

pkt_result send_icmp_down(struct nw_layer *self, struct pkt *packet);
pkt_result receive_icmp_up(struct nw_layer *self, struct pkt *packet);
uint16_t calc_packet_checksum(void *data, size_t len);
void echo_request_to_reply(struct pkt *packet, struct icmp_header *header, size_t len);

#ifdef __cplusplus
}
#endif
