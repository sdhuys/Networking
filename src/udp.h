#pragma once
#include "address_types.h"
#include "pkt_result.h"
#include "routing_table.h"
#include <stddef.h>
#include <stdint.h>

struct nw_layer;
struct pkt;

struct udp_context {
	struct socket_manager *sock_manager;
	struct routing_table *routing_table;
	struct nw_interface *nw_ifs;
	size_t if_count;
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
