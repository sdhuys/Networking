#pragma once
#include "layer.h"

int create_arp(struct nw_layer *self, struct nw_layer_data *payload);
int read_arp(struct nw_layer *self, const struct nw_layer_data *payload);