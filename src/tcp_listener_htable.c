#include "tcp_listener_htable.h"

bool add_to_tcp_listener_hashtable(struct tcp_ipv4_listener_htable_t *htable,
				   struct tcp_ipv4_listener_t *listener)
{
	uint32_t hash = calc_tcp_listener_hash(listener->local_port, listener->local_addr, htable);

	pthread_mutex_lock(&htable->bucket_locks[hash]);

	struct tcp_ipv4_listener_node_t *node = htable->buckets[hash];
	printf("NODE \n\n");

	while (node != NULL) {
		if (node->listener->local_port == listener->local_port) {
			pthread_mutex_unlock(&htable->bucket_locks[hash]);
			return false;
		}
		node = node->next;
	}

	retain_tcp_listener(listener);
	struct tcp_ipv4_listener_node_t *new_node = malloc(sizeof(struct tcp_ipv4_listener_node_t));
	if (new_node == NULL)
		return NULL;

	new_node->listener = listener;
	new_node->next = htable->buckets[hash];
	htable->buckets[hash] = new_node;
	pthread_mutex_unlock(&htable->bucket_locks[hash]);
	return true;
}

struct tcp_ipv4_listener_t *query_tcp_listener_hashtable(struct tcp_ipv4_listener_htable_t *htable,
							 uint16_t port,
							 ipv4_address addr)
{
	uint32_t hash = calc_tcp_listener_hash(port, addr, htable);
	struct tcp_ipv4_listener_node_t *bucket_node = htable->buckets[hash];

	pthread_mutex_t *lock = &(htable->bucket_locks[hash]);
	pthread_mutex_lock(lock);
	while (bucket_node != NULL) {
		struct tcp_ipv4_listener_t *listener = bucket_node->listener;
		if (listener->local_port == port && listener->state != TCP_LIS_CLOSED) {
			retain_tcp_listener(listener);
			pthread_mutex_unlock(lock);
			return listener;
		}
		bucket_node = bucket_node->next;
	}
	pthread_mutex_unlock(lock);
	return NULL;
}

bool remove_from_tcp_listener_hashtable(struct tcp_ipv4_listener_htable_t *htable,
					struct tcp_ipv4_listener_t *listener)
{
	uint32_t hash = calc_tcp_listener_hash(listener->local_port, listener->local_addr, htable);

	pthread_mutex_t *lock = &(htable->bucket_locks[hash]);
	pthread_mutex_lock(lock);

	struct tcp_ipv4_listener_node_t *node = htable->buckets[hash];
	struct tcp_ipv4_listener_node_t *prev = NULL;
	while (node != NULL) {
		if (node->listener == listener) {
			if (prev != NULL)
				prev->next = node->next;
			else
				htable->buckets[hash] = node->next;

			pthread_mutex_lock(&listener->lock);
			listener->state = TCP_LIS_CLOSED;
			pthread_mutex_unlock(&listener->lock);
			release_tcp_listener(listener);
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

uint32_t calc_tcp_listener_hash(uint16_t port,
				ipv4_address ip,
				struct tcp_ipv4_listener_htable_t *htable)
{
	unsigned char data[6];
	data[0] = port & 0xFF;
	data[1] = (port >> 8) & 0xFF;
	memcpy(&data[2], ip, IPV4_ADDR_LEN);
	return hash_table(data, sizeof(data)) & (htable->buckets_amount - 1);
}

struct tcp_ipv4_listener_htable_t *create_tcp_ipv4_listener_htable(size_t size)
{
	// enforce only power of 2 sizes
	if (size == 0 || (size & (size - 1)) != 0)
		return NULL;

	struct tcp_ipv4_listener_htable_t *tcp_lstnr_htable = malloc(sizeof(*tcp_lstnr_htable));
	if (!tcp_lstnr_htable)
		return NULL;

	tcp_lstnr_htable->buckets_amount = size;

	pthread_mutex_t *bckt_locks = malloc(sizeof(pthread_mutex_t) * size);
	if (!bckt_locks) {
		free(tcp_lstnr_htable);
		return NULL;
	}

	for (size_t i = 0; i < size; i++)
		pthread_mutex_init(&bckt_locks[i], NULL);

	tcp_lstnr_htable->bucket_locks = bckt_locks;

	struct tcp_ipv4_listener_node_t **buckets = calloc(size, sizeof(*buckets));
	if (!buckets) {
		free(bckt_locks);
		free(tcp_lstnr_htable);
		return NULL;
	}

	tcp_lstnr_htable->buckets = buckets;
	return tcp_lstnr_htable;
}
