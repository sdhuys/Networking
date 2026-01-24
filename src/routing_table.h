#pragma once
#include <arpa/inet.h>
#include <stdlib.h>
#include "types.h"

#ifdef __cplusplus
extern "C"
{
#endif

struct route *create_routing_table();
size_t get_init_routes_amount();

#ifdef __cplusplus
}
#endif
