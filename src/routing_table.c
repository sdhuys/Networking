#include "routing_table.h"
#include "nw_interface.h"
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>

#define ROUTES_PER_IF 2
#define LOOPBACK_ROUTES_PER_IF 2

struct routing_table *create_routing_table(
    struct nw_interface *interfaces,
    size_t if_count)
{
    if (!interfaces || if_count == 0)
        return NULL;

    size_t routes_count = 0;

    for (size_t i = 0; i < if_count; i++) {
        routes_count += (interfaces[i].flags & IF_LOOPBACK)
            ? LOOPBACK_ROUTES_PER_IF
            : ROUTES_PER_IF;
    }

    struct routing_table *table = malloc(sizeof(*table));
    if (!table)
        return NULL;

    struct route *routes = calloc(routes_count, sizeof(*routes));
    if (!routes) {
        free(table);
        return NULL;
    }

    table->routes = routes;
    table->count = routes_count;
    table->gen_id = 0;

    size_t route_i = 0;

    for (size_t i = 0; i < if_count; i++) {
        struct nw_interface *iface = &interfaces[i];

        // Loopback interface
        if (iface->flags & IF_LOOPBACK) {
            // Route 0: 127.0.0.0/8
            routes[route_i].prefix = htonl(0x7F000000);
            routes[route_i].subnet_mask = htonl(0xFF000000);
            routes[route_i].prefix_len = 8;
            routes[route_i].mtu = iface->mtu;
            routes[route_i].type = ROUTE_LOCAL;
            routes[route_i].gateway = 0;
            routes[route_i].nw_if_id = i;
            routes[route_i].gen_id = table->gen_id;

            route_i++;

            // Route 1: own address /32
            routes[route_i].prefix = htonl(iface->ipv4_addr);
            routes[route_i].subnet_mask = htonl(0xFFFFFFFF);
            routes[route_i].prefix_len = 32;
            routes[route_i].mtu = iface->mtu;
            routes[route_i].type = ROUTE_LOCAL;
            routes[route_i].gateway = 0;
            routes[route_i].nw_if_id = i;
            routes[route_i].gen_id = table->gen_id;

            route_i++;

            continue;
        }

        // Non-loopback interface

        uint32_t ip = iface->ipv4_addr;
        uint32_t mask = iface->subnet_mask;

        uint32_t network = ip & mask;
        uint8_t prefix_len = __builtin_popcount(mask);

        // Route 0: directly connected subnet
        routes[route_i].prefix = htonl(network);
        routes[route_i].subnet_mask = htonl(mask);
        routes[route_i].prefix_len = prefix_len;
        routes[route_i].mtu = iface->mtu;
        routes[route_i].type = ROUTE_ONLINK;
        routes[route_i].gateway = 0;
        routes[route_i].nw_if_id = i;
        routes[route_i].gen_id = table->gen_id;

        route_i++;

        // Route 1: default route via gateway (.1)
        uint32_t gateway = htonl(network) | 1;

        routes[route_i].prefix = 0;
        routes[route_i].subnet_mask = 0;
        routes[route_i].prefix_len = 0;
        routes[route_i].mtu = iface->mtu;
        routes[route_i].type = ROUTE_VIA;
        routes[route_i].gateway = htonl(gateway);
        routes[route_i].nw_if_id = i;
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