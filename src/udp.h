#pragma once
#include "types.h"

pkt_result send_udp_down(struct nw_layer *self, struct pkt *packet);
pkt_result receive_udp_up(struct nw_layer *self, struct pkt *packet);