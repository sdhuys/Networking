#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "types.h"

int start_listening(int fd, struct nw_layer *tap);
int send_up_to_ethernet(struct nw_layer *tap, const struct pkt *data);
int write_to_tap(struct nw_layer *tap, const struct pkt *data);