#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "buffer_pool.h"
#include "types.h"

int start_listening(int fd, struct nw_layer *tap);
pkt_result send_up_to_ethernet(struct nw_layer *tap, struct pkt *packet);
pkt_result write_to_tap(struct nw_layer *tap, struct pkt *packet);