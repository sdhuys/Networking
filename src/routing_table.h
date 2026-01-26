#pragma once
#include "types.h"
#include <arpa/inet.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

struct route_t *create_routing_table(struct nw_interface_t *nw_if);
size_t get_init_routes_amount();

#ifdef __cplusplus
}
#endif
