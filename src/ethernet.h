#pragma once
#include "address_types.h"
#include "pkt_result.h"
#include <stdbool.h>
#include <stdint.h>

struct nw_layer;
struct pkt;

struct ethernet_context {
	mac_address_t mac_addr;
};

struct ethernet_header {
	mac_address_t dest_mac;
	mac_address_t src_mac;
	uint16_t ethertype;
} __attribute__((packed));

#ifdef __cplusplus
extern "C" {
#endif

pkt_result receive_frame_up(struct nw_layer *self, struct pkt *packet);
pkt_result send_frame_down(struct nw_layer *self, struct pkt *packet);
void print_incoming(struct ethernet_header *header);
bool relevant_destination_mac(mac_address_t dest_mac, struct nw_layer *self);

#ifdef __cplusplus
}
#endif
