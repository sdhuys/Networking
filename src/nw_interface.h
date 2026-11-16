#pragma once
#include "address_types.h"
#include "pkt_result.h"
#include <net/if.h>
#include <stdint.h>

#define IF_NOARP 0x1
#define IF_LOOPBACK 0x2

struct pkt;
struct nw_layer;

struct interface_context {
	struct nw_interface *interfaces;
	size_t if_amount;
	struct queue *ingress_q;
};

typedef pkt_result (*nw_if_transmit_fn)(struct interface_context *if_cntx,
					struct nw_interface *nw_if,
					struct pkt *p);

struct nw_interface {
	char name[IFNAMSIZ];
	size_t index;	// index in interface_context->interfaces
	int fd;		// -1 for loopback
	uint32_t flags; // IF_NOARP, IF_LOOPBACK
	ipv4_address_t ipv4_addr;
	ipv4_address_t subnet_mask;
	mac_address_t mac_addr;
	uint32_t mtu;
	nw_if_transmit_fn transmit;
};

#ifdef __cplusplus
extern "C" {
#endif

void read_from_interface(struct nw_layer *if_layer);
void process_ingress_q_packets(struct nw_layer *interface);
pkt_result send_up_to_ethernet(struct nw_layer *interface, struct pkt *packet);
pkt_result gen_interface_transmit(struct nw_layer *interface, struct pkt *packet);
pkt_result tap_transmit(struct interface_context *ctx, struct nw_interface *nif, struct pkt *p);
pkt_result loopback_transmit(struct interface_context *ctx,
			     struct nw_interface *nif,
			     struct pkt *p);

void set_nw_if_struct(struct nw_interface *nw_if,
		      int tap_fd,
		      char *if_name,
		      const mac_address_t mac_addr,
		      const ipv4_address_t ip_addr,
		      const ipv4_address_t subnet_mask,
		      const uint32_t mtu,
		      nw_if_transmit_fn tx_function,
		      uint32_t flags);

#ifdef __cplusplus
}
#endif
