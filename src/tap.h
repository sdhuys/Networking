#pragma once
#include "buffer_pool.h"
#include "timer.h"
#include "types.h"
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

int start_listening(struct nw_layer_t *interface);
pkt_result send_up_to_ethernet(struct nw_layer_t *tap, struct pkt_t *packet);
pkt_result write_to_interface(struct nw_layer_t *tap, struct pkt_t *packet);

#ifdef __cplusplus
}
#endif
