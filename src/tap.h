#pragma once
#include "buffer_pool.h"
#include "types.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

int start_listening(int fd, struct nw_layer *tap);
pkt_result send_up_to_ethernet(struct nw_layer *tap, struct pkt *packet);
pkt_result write_to_tap(struct nw_layer *tap, struct pkt *packet);

#ifdef __cplusplus
}
#endif
