#pragma once
#include "hash.h"
#include "tcp_conn_socket.h"
#include "types.h"

struct tcp_ipv4_conn_htable {
	struct tcp_ipv4_conn_htbl_node **buckets;
	uint32_t buckets_amount;
	pthread_mutex_t *bucket_locks; // lock per bucket
	size_t count;
};

struct tcp_ipv4_conn_htbl_node {
	struct tcp_ipv4_conn *conn;
	struct tcp_ipv4_conn_htbl_node *next;
};

bool add_to_tcp_conn_hashtable(struct tcp_ipv4_conn_htable *htable, struct tcp_ipv4_conn *conn);
struct tcp_ipv4_conn *query_tcp_conn_hashtable(struct tcp_ipv4_conn_htable *htable,
					       struct tcp_conn_id id);
bool remove_from_tcp_conn_hashtable(struct tcp_ipv4_conn_htable *htable,
				    struct tcp_ipv4_conn *conn);
uint32_t calc_tcp_conn_hash(struct tcp_ipv4_conn_htable *htable, struct tcp_conn_id id);
struct tcp_ipv4_conn_htable *create_tcp_ipv4_conn_htable(size_t size);
bool is_tcp_conn_match(struct tcp_ipv4_conn *conn, struct tcp_conn_id id);
