#pragma once
#include "types.h"

int send_udp_down(struct nw_layer *self, const struct pkt *data);
int receive_udp_up(struct nw_layer *self, const struct pkt *data);