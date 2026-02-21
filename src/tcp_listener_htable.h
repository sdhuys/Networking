#pragma once
#include "hash.h"
#include "tcp_listener_socket.h"
#include "types.h"
#include <stdlib.h>

struct tcp_ipv4_listener_node {
	struct tcp_ipv4_listener *listener;
	struct tcp_ipv4_listener_node *next;
};

struct tcp_ipv4_listener_htable {
	struct tcp_ipv4_listener_node **buckets;
	uint32_t buckets_amount;
	pthread_mutex_t *bucket_locks; // lock per bucket
};

bool add_to_tcp_listener_hashtable(struct tcp_ipv4_listener_htable *htable,
				   struct tcp_ipv4_listener *socket);
struct tcp_ipv4_listener *query_tcp_listener_hashtable(struct tcp_ipv4_listener_htable *htable,
						       uint16_t port,
						       ipv4_address addr);
bool remove_from_tcp_listener_hashtable(struct tcp_ipv4_listener_htable *htable,
					struct tcp_ipv4_listener *socket);
uint32_t calc_tcp_listener_hash(uint16_t port,
				ipv4_address ip,
				struct tcp_ipv4_listener_htable *htable);
struct tcp_ipv4_listener_htable *create_tcp_ipv4_listener_htable(size_t size);
bool is_tcp_lstnr_match(struct tcp_ipv4_listener *lstnr, uint16_t loc_port, ipv4_address loc_addr);