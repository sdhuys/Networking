#pragma once
#include "address_types.h"
#include "pkt_result.h"
#include <stdint.h>

#define ECHO_REPLY 0
#define DESTINATION_UNREACHABLE 3
#define ECHO_REQUEST 8

struct pkt;
struct nw_layer;

struct icmp_context {
};

struct icmp_header {
	unsigned char type;
	unsigned char code;
	uint16_t checksum;
	uint32_t var_rest_of_header;
} __attribute__((packed));

#ifdef __cplusplus
extern "C" {
#endif

pkt_result send_icmp_down(struct nw_layer *self, struct pkt *packet);
pkt_result receive_icmp_up(struct nw_layer *self, struct pkt *packet);
void echo_request_to_reply(struct pkt *packet, struct icmp_header *header);

#ifdef __cplusplus
}
#endif
