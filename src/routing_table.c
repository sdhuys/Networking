#include "routing_table.h"
#define ROUTES_PER_IF 2 // one direcly connected on_link, one via gateway

struct routing_table *create_routing_table(struct nw_interface *interfaces, size_t if_count)
{
	if (!interfaces || if_count == 0)
		return NULL;

	size_t routes_count = if_count * ROUTES_PER_IF;
	struct routing_table *table = malloc(sizeof(*table));
	if (!table)
		return NULL;

	struct route *routes = malloc(routes_count * sizeof(struct route));
	if (!routes) {
		free(table);
		return NULL;
	}

	table->routes = routes;
	table->count = routes_count;
	table->gen_id = 0;

	size_t route_i = 0;

	for (size_t i = 0; i < if_count; i++) {
		uint32_t ip = ntohl(interfaces[i].ipv4_addr);
		uint32_t mask = ntohl(interfaces[i].subnet_mask);

		uint32_t network = ip & mask;
		uint8_t prefix_len = __builtin_popcount(mask);

		// Route 0: directly connected subnet
		routes[route_i].prefix = htonl(network);
		routes[route_i].subnet_mask = htonl(mask);
		routes[route_i].prefix_len = prefix_len;
		routes[route_i].mtu = interfaces[i].mtu;
		routes[route_i].type = ROUTE_ONLINK;
		routes[route_i].gateway = 0;
		routes[route_i].iface_id = i; // only one interface for now
		routes[route_i].gen_id = table->gen_id;

		route_i++;

		// Route 1: default route via gateway (assume .1)
		uint32_t gateway = network | 1;

		routes[route_i].prefix = 0;
		routes[route_i].subnet_mask = 0;
		routes[route_i].prefix_len = 0;
		routes[route_i].mtu = interfaces[i].mtu;
		routes[route_i].type = ROUTE_VIA;
		routes[route_i].gateway = htonl(gateway);
		routes[route_i].iface_id = i;
		routes[route_i].gen_id = table->gen_id;
		route_i++;
	}

	return table;
}

bool get_route(struct routing_table *table, ipv4_address_t dest_ip, struct route **route_out)
{
	int longest_prefix = -1;
	struct route *best_match = NULL; // keep track of the best one found so far

	uint32_t int_ip;
	memcpy(&int_ip, dest_ip, IPV4_ADDR_LEN);

	for (size_t i = 0; i < table->count; i++) {
		struct route *route = &table->routes[i];

		// check if it matches AND if it's better than our current best
		if (((int_ip & route->subnet_mask) == route->prefix) &&
		    (route->prefix_len > longest_prefix)) {

			longest_prefix = route->prefix_len;
			best_match = route;
		}
	}

	if (best_match) {
		*route_out = best_match;
		return true;
	}
	*route_out = NULL;
	return false;
}