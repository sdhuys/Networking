#pragma once
#include "address_types.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum {
	ROUTE_ONLINK, // destination is directly reachable
	ROUTE_VIA     // send via gateway
} route_type;

struct nw_interface;

struct route {
	uint32_t prefix;      // network byte order
	uint32_t subnet_mask; // network byte order
	uint8_t prefix_len;   // CIDR mask (0–32)
	uint32_t mtu;	      // max transmission unit
	route_type type;
	uint32_t gateway; // valid only if type == ROUTE_VIA
	uint32_t iface_id;

	// to keep track of validity of route when we add routing adding/removing
	uint32_t gen_id;
};

struct routing_table {
	struct route *routes;
	size_t count;
	uint32_t gen_id;
};

#ifdef __cplusplus
extern "C" {
#endif

struct routing_table *create_routing_table(struct nw_interface *nw_if, size_t count);
bool get_route(struct routing_table *table, ipv4_address_t dest_ip, struct route **route_out);

#ifdef __cplusplus
}
#endif
