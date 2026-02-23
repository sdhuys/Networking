#pragma once
#include "hash.h"
#include "types.h"
#include <stdlib.h>

struct udp_ipv4_socket;

struct udp_ipv4_sckt_htable_node {
	struct udp_ipv4_socket *socket;
	struct udp_ipv4_sckt_htable_node *next;
};

struct udp_ipv4_sckt_htable {
	struct udp_ipv4_sckt_htable_node **buckets;
	uint32_t buckets_amount;
	pthread_mutex_t *bucket_locks; // One lock per bucket
};

bool add_to_udp_hashtable(struct udp_ipv4_sckt_htable *htable, struct udp_ipv4_socket *socket);
struct udp_ipv4_socket *query_udp_hashtable(struct udp_ipv4_sckt_htable *htable,
					    uint16_t port,
					    ipv4_address_t addr);
bool remove_from_udp_hashtable(struct udp_ipv4_sckt_htable *htable, struct udp_ipv4_socket *socket);
uint32_t calc_udp_hash(uint16_t port, ipv4_address_t ip, struct udp_ipv4_sckt_htable *htable);
struct udp_ipv4_sckt_htable *create_udp_ipv4_sckt_htable(size_t size);
