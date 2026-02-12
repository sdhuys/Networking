#pragma once
#include "tcp_listener_socket.h"
#include "types.h"
#include <stdlib.h>

bool add_to_tcp_lstnr_hashtable(struct tcp_ipv4_listener_htable_t *htable,
				struct tcp_ipv4_listener_t *socket);
struct tcp_ipv4_listener_t *query_tcp_lstnr_hashtable(struct tcp_ipv4_listener_htable_t *htable,
						      uint16_t port,
						      ipv4_address addr);
bool remove_from_tcp_lstnr_hashtable(struct tcp_ipv4_listener_htable_t *htable,
				     struct tcp_ipv4_listener_t *socket);
uint32_t calc_tcp_lstnr_hash(uint16_t port,
			     ipv4_address ip,
			     struct tcp_ipv4_listener_htable_t *htable);

struct tcp_ipv4_listener_node_t {
	struct tcp_ipv4_listener_t *listener;
	struct tcp_ipv4_listener_node_t *next;
};

struct tcp_ipv4_listener_htable_t {
	struct tcp_ipv4_listener_node_t **buckets;
	uint8_t buckets_amount;
	pthread_mutex_t *bucket_locks; // lock per bucket
};