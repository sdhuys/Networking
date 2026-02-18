#include "tcp_conn_htable.h"

bool add_to_tcp_conn_hashtable(struct tcp_ipv4_conn_htable *htable, struct tcp_ipv4_conn *conn)
{
	uint32_t hash = calc_tcp_conn_hash(
	    htable, conn->local_port, conn->local_addr, conn->extern_port, conn->extern_addr);

	pthread_mutex_lock(&htable->bucket_locks[hash]);

	struct tcp_ipv4_conn_htbl_node *node = htable->buckets[hash];
	while (node != NULL) {
		struct tcp_ipv4_conn *node_conn = node->conn;
		if (is_tcp_conn_match(conn,
				      node_conn->local_port,
				      node_conn->local_addr,
				      node_conn->extern_port,
				      node_conn->extern_addr)) {
			pthread_mutex_unlock(&htable->bucket_locks[hash]);
			return false;
		}
		node = node->next;
	}

	struct tcp_ipv4_conn_htbl_node *new_node = malloc(sizeof(struct tcp_ipv4_conn_htbl_node));
	if (new_node == NULL)
		return false;

	new_node->conn = conn;
	new_node->next = htable->buckets[hash];
	htable->buckets[hash] = new_node;
	pthread_mutex_unlock(&htable->bucket_locks[hash]);
	return true;
}

// does not check state (different hashtables, each different state requirements!)
struct tcp_ipv4_conn *query_tcp_conn_hashtable(struct tcp_ipv4_conn_htable *htable,
					       uint16_t loc_port,
					       ipv4_address loc_addr,
					       uint16_t extern_port,
					       ipv4_address extern_addr)
{
	uint32_t hash = calc_tcp_conn_hash(htable, loc_port, loc_addr, extern_port, extern_addr);
	struct tcp_ipv4_conn_htbl_node *bucket_node = htable->buckets[hash];

	pthread_mutex_t *lock = &(htable->bucket_locks[hash]);
	pthread_mutex_lock(lock);
	while (bucket_node != NULL) {
		struct tcp_ipv4_conn *conn = bucket_node->conn;
		if (is_tcp_conn_match(conn, loc_port, loc_addr, extern_port, extern_addr)) {
			pthread_mutex_unlock(lock);
			return bucket_node->conn;
		}
		bucket_node = bucket_node->next;
	}
	pthread_mutex_unlock(lock);
	return NULL;
}

// does not change state (different hashtables, each different state requirements!)
bool remove_from_tcp_conn_hashtable(struct tcp_ipv4_conn_htable *htable, struct tcp_ipv4_conn *conn)
{
	uint32_t hash = calc_tcp_conn_hash(
	    htable, conn->local_port, conn->local_addr, conn->extern_port, conn->extern_addr);

	pthread_mutex_t *lock = &(htable->bucket_locks[hash]);
	pthread_mutex_lock(lock);

	struct tcp_ipv4_conn_htbl_node *node = htable->buckets[hash];
	struct tcp_ipv4_conn_htbl_node *prev = NULL;
	while (node != NULL) {
		if (node->conn == conn) {
			if (prev != NULL)
				prev->next = node->next;
			else
				htable->buckets[hash] = node->next;

			/*
				    pthread_mutex_lock(&conn->lock);
				    conn->state = TCP_CLOSED;
				    pthread_mutex_unlock(&conn->lock);
			*/

			free(node);
			pthread_mutex_unlock(lock);
			return true;
		}
		prev = node;
		node = node->next;
	}
	pthread_mutex_unlock(lock);
	return false;
}

uint32_t calc_tcp_conn_hash(struct tcp_ipv4_conn_htable *htable,
			    uint16_t local_port,
			    ipv4_address local_addr,
			    uint16_t extern_port,
			    ipv4_address extern_addr)
{
	unsigned char data[12];
	data[0] = local_port & 0xFF;
	data[1] = (local_port >> 8) & 0xFF;
	memcpy(&data[2], local_addr, IPV4_ADDR_LEN);
	data[6] = extern_port & 0xFF;
	data[7] = (extern_port >> 8) & 0xFF;
	memcpy(&data[8], extern_addr, IPV4_ADDR_LEN);
	return hash_table(data, sizeof(data)) & (htable->buckets_amount - 1);
}

struct tcp_ipv4_conn_htable *create_tcp_ipv4_conn_htable(size_t size)
{
	// enforce only power of 2 sizes
	if (size == 0 || (size & (size - 1)) != 0)
		return NULL;

	struct tcp_ipv4_conn_htable *tcp_conn_htable = malloc(sizeof(*tcp_conn_htable));
	if (!tcp_conn_htable)
		return NULL;

	tcp_conn_htable->buckets_amount = size;

	pthread_mutex_t *bckt_locks = malloc(sizeof(pthread_mutex_t) * size);
	if (!bckt_locks) {
		free(tcp_conn_htable);
		return NULL;
	}

	for (size_t i = 0; i < size; i++)
		pthread_mutex_init(&bckt_locks[i], NULL);

	tcp_conn_htable->bucket_locks = bckt_locks;

	struct tcp_ipv4_conn_htbl_node **buckets = calloc(size, sizeof(*buckets));
	if (!buckets) {
		free(bckt_locks);
		free(tcp_conn_htable);
		return NULL;
	}

	tcp_conn_htable->buckets = buckets;
	tcp_conn_htable->count = 0;
	return tcp_conn_htable;
}

bool is_tcp_conn_match(struct tcp_ipv4_conn *conn,
		       uint16_t loc_port,
		       ipv4_address loc_addr,
		       uint16_t extern_port,
		       ipv4_address extern_addr)
{
	return conn->extern_port == extern_port && conn->local_port == loc_port &&
	       memcmp(conn->local_addr, loc_addr, IPV4_ADDR_LEN) == 0 &&
	       memcmp(conn->extern_addr, extern_addr, IPV4_ADDR_LEN) == 0;
}