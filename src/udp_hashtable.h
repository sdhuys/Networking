#pragma once
#include "types.h"
#include "udp_socket.h"
#include <stdlib.h>

bool add_to_hashtable(struct udp_ipv4_sckt_htable_t *htable, struct udp_ipv4_socket_t *socket);
struct udp_ipv4_socket_t *query_hashtable(struct udp_ipv4_sckt_htable_t *htable,
					  uint16_t dest_port);
bool remove_from_udp_hashtable(struct udp_ipv4_sckt_htable_t *htable,
			       struct udp_ipv4_socket_t *socket);
uint32_t calc_hash(uint16_t port, struct udp_ipv4_sckt_htable_t *htable);

struct udp_ipv4_sckt_htable_node_t {
	struct udp_ipv4_socket_t *socket;
	struct udp_ipv4_sckt_htable_node_t *next;
};

struct udp_ipv4_sckt_htable_t {
	struct udp_ipv4_sckt_htable_node_t **buckets;
	uint16_t buckets_amount;
	pthread_mutex_t *bucket_locks; // One lock per bucket
};