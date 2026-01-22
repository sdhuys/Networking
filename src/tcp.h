#pragma once
#include "types.h"

pkt_result send_tcp_down(struct nw_layer *self, struct pkt *packet);
pkt_result receive_tcp_up(struct nw_layer *self, struct pkt *packet);