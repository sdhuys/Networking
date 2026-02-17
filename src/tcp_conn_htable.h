#pragma once
#include "hash.h"
#include "tcp_conn_socket.h"
#include "types.h"

struct tcp_ipv4_conn_htable_t {
	struct tcp_ipv4_conn_htbl_node_t **buckets;
	uint32_t buckets_amount;
	pthread_mutex_t *bucket_locks; // lock per bucket
	size_t count;
};

struct tcp_ipv4_conn_htbl_node_t {
	struct tcp_ipv4_conn_t *conn;
	struct tcp_ipv4_conn_htbl_node_t *next;
};

bool add_to_tcp_conn_hashtable(struct tcp_ipv4_conn_htable_t *htable, struct tcp_ipv4_conn_t *conn);
struct tcp_ipv4_conn_t *query_tcp_conn_hashtable(struct tcp_ipv4_conn_htable_t *htable,
						 uint16_t loc_port,
						 ipv4_address loc_addr,
						 uint16_t rem_port,
						 ipv4_address rem_addr);
bool remove_from_tcp_conn_hashtable(struct tcp_ipv4_conn_htable_t *htable,
				    struct tcp_ipv4_conn_t *conn);
uint32_t calc_tcp_conn_hash(struct tcp_ipv4_conn_htable_t *htable,
			    uint16_t loc_port,
			    ipv4_address loc_addr,
			    uint16_t rem_port,
			    ipv4_address rem_addr);
struct tcp_ipv4_conn_htable_t *create_tcp_ipv4_conn_htable(size_t size);
bool is_tcp_conn_match(struct tcp_ipv4_conn_t *conn,
		       uint16_t loc_port,
		       ipv4_address loc_addr,
		       uint16_t extern_port,
		       ipv4_address extern_addr);
