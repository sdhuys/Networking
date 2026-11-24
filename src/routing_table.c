#include "routing_table.h"
#include "nw_interface.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint32_t addr_u32(const ipv4_address_t a)
{
	uint32_t x;
	memcpy(&x, a, IPV4_ADDR_LEN);
	return x;
}

// prefix, mask and gateway in network byte order
static void set_route(struct route *r,
		      uint32_t prefix,
		      uint32_t mask,
		      route_type type,
		      uint32_t gateway,
		      const struct nw_interface *nw_if,
		      uint32_t gen_id)
{
	r->prefix = prefix & mask;
	r->subnet_mask = mask;
	r->prefix_len = (uint8_t)__builtin_popcount(mask);
	r->mtu = nw_if->mtu;
	r->type = type;
	r->gateway = gateway;
	r->nw_if_id = (uint32_t)nw_if->index;
	r->gen_id = gen_id;
}

// Routes per interface:
//   loopback:  its own range (127.0.0.0/8)                        -> lo
//   other:     its own address /32 (only if there is a loopback)  -> lo
//              its subnet, on-link                                -> this interface
//              default route via host of its subnet               -> this interface
//
// longest-prefix match: /32 wins over the subnet route => traffic to the
// stack's own address never leaves the stack
struct routing_table *create_routing_table(struct nw_interface *interfaces,
					   size_t if_count,
					   const struct static_route *statics,
					   size_t static_count)
{
	if (!interfaces || if_count == 0)
		return NULL;

	const struct nw_interface *lo = NULL;
	for (size_t i = 0; i < if_count; i++) {
		if (interfaces[i].flags & IF_LOOPBACK) {
			lo = &interfaces[i];
			break;
		}
	}

	size_t routes_count = static_count;
	for (size_t i = 0; i < if_count; i++)
		routes_count += (interfaces[i].flags & IF_LOOPBACK) ? 1 : (lo ? 2 : 1);

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

	size_t n = 0;
	for (size_t i = 0; i < if_count; i++) {
		const struct nw_interface *nw_if = &interfaces[i];
		uint32_t ip = addr_u32(nw_if->ipv4_addr);
		uint32_t mask = addr_u32(nw_if->subnet_mask);

		if (nw_if->flags & IF_LOOPBACK) {
			set_route(&routes[n++], ip, mask, ROUTE_LOCAL, 0, nw_if, table->gen_id);
			continue;
		}

		if (lo)
			set_route(&routes[n++], ip, 0xFFFFFFFF, ROUTE_LOCAL, 0, lo, table->gen_id);
		set_route(&routes[n++], ip, mask, ROUTE_ONLINK, 0, nw_if, table->gen_id);
	}

	// look for the network interface the static route can use
	for (size_t s = 0; s < static_count; s++) {
		uint32_t gw = addr_u32(statics[s].gateway);
		const struct nw_interface *out = NULL;
		for (size_t i = 0; i < if_count && !out; i++) {
			const struct nw_interface *nw_if = &interfaces[i];
			uint32_t m = addr_u32(nw_if->subnet_mask);

			// if this nw_if is not loopback, and the gateway and nw_if's ip are on the
			// same subnet
			if (!(nw_if->flags & IF_LOOPBACK) &&
			    (gw & m) == (addr_u32(nw_if->ipv4_addr) & m))
				out = nw_if;
		}
		if (!out) {
			free(routes);
			free(table);
			fprintf(stderr,
				"route: gateway provided that's not on any connected subnet\n");
			return NULL;
		}

		set_route(&routes[n++],
			  addr_u32(statics[s].prefix),
			  addr_u32(statics[s].mask),
			  ROUTE_VIA,
			  gw,
			  out,
			  table->gen_id);

		assert(n == routes_count);
		return table;
	}
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