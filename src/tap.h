#pragma once
#include "pkt_result.h"
#include <stddef.h>

struct pkt;
struct nw_layer;
struct nw_interface;

struct interface_context {
	struct nw_interface *interfaces;
	size_t if_amount;
};

#ifdef __cplusplus
extern "C" {
#endif

void start_listening(struct nw_layer *interface);
pkt_result send_up_to_ethernet(struct nw_layer *tap, struct pkt *packet);
pkt_result write_to_interface(struct nw_layer *tap, struct pkt *packet);

#ifdef __cplusplus
}
#endif
