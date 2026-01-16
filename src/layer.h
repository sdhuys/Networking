#pragma once
#include <stddef.h>

struct nw_layer_data
{
    unsigned char *data;
    size_t len;
};

struct nw_layer
{
    char *name;
    int (*process_for_down)(struct nw_layer *self, struct nw_layer_data *payload);
    int (*process_for_up)(struct nw_layer *self, struct nw_layer_data *raw_data);
    struct nw_layer **ups;
    struct nw_layer *down;
    size_t ups_amount;
    void * context;
};