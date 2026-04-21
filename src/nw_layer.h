#pragma once
#include "pkt_result.h"
#include <stddef.h>

struct pkt;

struct nw_layer {
	char *name;
	pkt_result (*send_down)(struct nw_layer *self, struct pkt *packet);
	pkt_result (*rcv_up)(struct nw_layer *self, struct pkt *packet);
	struct nw_layer **ups;
	struct nw_layer **downs;
	size_t ups_count;
	size_t downs_count;
	void *context;
};
