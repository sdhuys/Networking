#pragma once
#include "nw_interface.h"
#include "types.h"
#include <arpa/inet.h>
#include <stdlib.h>

typedef enum {
	ROUTE_ONLINK, // destination is directly reachable
	ROUTE_VIA     // send via gateway
} route_type;

struct route {
	uint32_t prefix;      // network byte order
	uint32_t subnet_mask; // network byte order
	uint8_t prefix_len;   // CIDR mask (0–32)
	uint8_t mtu;	      // max transmission unit
	route_type type;
	uint32_t gateway; // valid only if type == ROUTE_VIA
	uint32_t iface_id;

	/*no mechanism for updating routing table yet, but on potential future route deletion: set
	flag to false, start timer for actual deletion.

	tcp connections store route pointer, if still_valid => write pointer to pkt metadata, else
	new lookup. this should give time for connections to update their routes or close before
	remove timer runs out and deletes route entry*/
	bool still_valid;
};

struct routing_table {
	struct route *routes;
	size_t count;
};

#ifdef __cplusplus
extern "C" {
#endif

struct routing_table *create_routing_table(struct nw_interface *nw_if, size_t count);
bool get_route(struct routing_table *table, ipv4_address_t dest_ip, struct route **route_out);

#ifdef __cplusplus
}
#endif
