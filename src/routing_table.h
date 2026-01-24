#pragma once
#include "types.h"
#include <arpa/inet.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

struct route *create_routing_table();
size_t get_init_routes_amount();

#ifdef __cplusplus
}
#endif
