#include "routing_table.h"
static size_t init_routes_amount = 2;

size_t get_init_routes_amount()
{
	return init_routes_amount;
}

struct route *create_routing_table(struct nw_interface *nw_if)
{
	struct route *routes = malloc(init_routes_amount * sizeof(struct route));
	if (!routes)
		return NULL;

	uint32_t ip = ntohl(nw_if->ipv4_addr);
	uint32_t mask = ntohl(nw_if->subnet_mask);

	uint32_t network = ip & mask;
	uint8_t prefix_len = __builtin_popcount(mask);

	// Route 0: directly connected subnet
	routes[0].prefix = htonl(network);
	routes[0].subnet_mask = htonl(mask);
	routes[0].prefix_len = prefix_len;
	routes[0].mtu = nw_if->mtu;
	routes[0].type = ROUTE_ONLINK;
	routes[0].gateway = 0;
	routes[0].iface_id = 0; // only one interface for now

	// Route 1: default route via gateway (assume .1)
	uint32_t gateway = network | 1;

	routes[1].prefix = 0;
	routes[1].subnet_mask = 0;
	routes[1].prefix_len = 0;
	routes[1].mtu = nw_if->mtu;
	routes[1].type = ROUTE_VIA;
	routes[1].gateway = htonl(gateway);
	routes[1].iface_id = 0;

	return routes;
}
