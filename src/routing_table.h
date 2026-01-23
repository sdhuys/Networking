#pragma once
#include <arpa/inet.h>
#include <stdlib.h>
#include "types.h"

struct route *create_routing_table();
size_t get_init_routes_amount();