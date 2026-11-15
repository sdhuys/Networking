#pragma once
#include "pkt_result.h"
#include "queue.h"
#include <stddef.h>

#define LOOPBACK_QUEUE_CAP 256

struct pkt;
struct nw_layer;
struct nw_interface;

struct interface_context {
	struct nw_interface *interfaces;
	size_t if_amount;
	struct queue *ingress_q;
};

#ifdef __cplusplus
extern "C" {
#endif

void *read_from_interface(void *i_face);
void process_ingress_q_packets(struct nw_layer *interface);
pkt_result send_up_to_ethernet(struct nw_layer *tap, struct pkt *packet);
pkt_result write_to_interface(struct nw_layer *tap, struct pkt *packet);

#ifdef __cplusplus
}
#endif
