#include "routing_table.h"
static size_t init_routes_amount = 2;

size_t get_init_routes_amount()
{
	return init_routes_amount;
}

struct route *create_routing_table()
{
	// avoid garbage when routes_amount is changed but extra routes not set
	struct route *routes = calloc(init_routes_amount, sizeof(struct route));
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