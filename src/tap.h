#pragma once
#include <stdio.h>
#include <unistd.h>
#include "layer.h"

int start_listening(int fd, struct nw_layer *tap);
int send_to_ethernet(struct nw_layer *tap, struct nw_layer_data *data);
int write_to_tap(struct nw_layer *tap, struct nw_layer_data *data);