#include "tcp_listener_htable.h"

bool add_to_tcp_lstnr_hashtable(struct tcp_ipv4_listener_htable_t *htable,
				struct tcp_ipv4_listener_t *socket)
{
	uint32_t hash = calc_tcp_lstnr_hash(socket->local_port, socket->local_addr, htable);

	pthread_mutex_lock(&htable->bucket_locks[hash]);

	struct tcp_ipv4_listener_node_t *node = htable->buckets[hash];
	while (node != NULL) {
		if (node->listener->local_port == socket->local_port) {
			pthread_mutex_unlock(&htable->bucket_locks[hash]);
			return false;
		}
		node = node->next;
	}

	struct tcp_ipv4_listener_node_t *new_node = malloc(sizeof(struct tcp_ipv4_listener_node_t));
	if (new_node == NULL)
		return NULL;

	new_node->listener = socket;
	new_node->next = htable->buckets[hash];
	htable->buckets[hash] = new_node;
	pthread_mutex_unlock(&htable->bucket_locks[hash]);
	return true;
}

struct tcp_ipv4_listener_t *query_tcp_lstnr_hashtable(struct tcp_ipv4_listener_htable_t *htable,
						      uint16_t port,
						      ipv4_address addr)
{
	uint32_t hash = calc_tcp_lstnr_hash(port, addr, htable);
	struct tcp_ipv4_listener_node_t *bucket_node = htable->buckets[hash];

	pthread_mutex_t *lock = &(htable->bucket_locks[hash]);
	pthread_mutex_lock(lock);
	while (bucket_node != NULL) {
		struct tcp_ipv4_listener_t *socket = bucket_node->listener;
		if (socket->local_port == port && socket->state != TCP_CLOSED) {
			pthread_mutex_unlock(lock);
			return bucket_node->listener;
		}
		bucket_node = bucket_node->next;
	}
	pthread_mutex_unlock(lock);
	return NULL;
}

bool remove_from_tcp_lstnr_hashtable(struct tcp_ipv4_listener_htable_t *htable,
				     struct tcp_ipv4_listener_t *socket)
{
	uint32_t hash = calc_tcp_lstnr_hash(socket->local_port, socket->local_addr, htable);

	pthread_mutex_t *lock = &(htable->bucket_locks[hash]);
	pthread_mutex_lock(lock);

	struct tcp_ipv4_listener_node_t *node = htable->buckets[hash];
	struct tcp_ipv4_listener_node_t *prev = NULL;
	while (node != NULL) {
		if (node->listener == socket) {
			if (prev != NULL)
				prev->next = node->next;
			else
				htable->buckets[hash] = node->next;

			pthread_mutex_lock(&socket->lock);
			socket->state = TCP_CLOSED;
			pthread_mutex_unlock(&socket->lock);

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

// succeptible to hash flooding attack
uint32_t calc_tcp_lstnr_hash(uint16_t port,
			     ipv4_address ip,
			     struct tcp_ipv4_listener_htable_t *htable)
{
	uint32_t ip_val;
	memcpy(&ip_val, ip, sizeof(uint32_t));
	uint32_t hash = port * GOLDEN_RATIO_32;
	hash = (hash ^ ip_val) * GOLDEN_RATIO_32;
	hash ^= hash >> 16;
	return (uint32_t)hash & (htable->buckets_amount - 1);
}