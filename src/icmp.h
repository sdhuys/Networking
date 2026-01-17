#pragma once
#include "types.h"

int send_icmp_down(struct nw_layer *self, const struct pkt *data);
int receive_icmp_up(struct nw_layer *self, const struct pkt *data);