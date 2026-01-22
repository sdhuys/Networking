#include "routing_table.h"

struct route *create_routing_table()
{
    struct route *routes = malloc(sizeof(struct route) * 2);
    if (routes == NULL)
        return NULL;

    // Route 0: Local Subnet
    // 0xC0A86400 -> 192.168.100.0
    routes[0] = (struct route){.prefix = htonl(0xC0A86400),
                        .prefix_len = 24, // /24 mask
                        .type = ROUTE_ONLINK};

    // Route 1: Default Gateway
    // 0x00000000 -> 0.0.0.0
    // 0xC0A86401 -> 192.168.100.1
    routes[1] = (struct route){.prefix = htonl(0x00000000),
                        .prefix_len = 0, // /0 mask (default)
                        .type = ROUTE_VIA,
                        .gateway = htonl(0xC0A86401)};

    return routes;
}