#pragma once
#include "address_types.h"
#include "pkt_result.h"
#include <stdint.h>

struct nw_layer;
struct pkt;

struct udp_context {
	ipv4_address_t stack_ipv4_addr;
	struct socket_manager *sock_manager;
};

struct udp_header {
	uint16_t src_port;
	uint16_t dest_port;
	uint16_t length;
	uint16_t checksum;
} __attribute__((packed));

#ifdef __cplusplus
extern "C" {
#endif

pkt_result send_udp_down(struct nw_layer *self, struct pkt *packet);
pkt_result receive_udp_up(struct nw_layer *self, struct pkt *packet);

#ifdef __cplusplus
}
#endif
