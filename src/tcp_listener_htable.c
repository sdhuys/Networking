#include "tcp_listener_htable.h"

bool add_to_tcp_listener_hashtable(struct tcp_ipv4_listener_htable *htable,
				   struct tcp_ipv4_listener *listener)
{
	uint32_t hash = calc_tcp_listener_hash(listener->local_port, listener->local_addr, htable);

	pthread_mutex_lock(&htable->bucket_locks[hash]);

	struct tcp_ipv4_listener_node *node = htable->buckets[hash];
	while (node != NULL) {
		struct tcp_ipv4_listener *bucket_lstnr = node->listener;
		if (is_tcp_lstnr_match(
			listener, bucket_lstnr->local_port, bucket_lstnr->local_addr)) {
			pthread_mutex_unlock(&htable->bucket_locks[hash]);
			return false;
		}
		node = node->next;
	}

	retain_tcp_listener(listener);
	struct tcp_ipv4_listener_node *new_node = malloc(sizeof(struct tcp_ipv4_listener_node));
	if (new_node == NULL)
		return false;

	new_node->listener = listener;
	new_node->next = htable->buckets[hash];
	htable->buckets[hash] = new_node;
	pthread_mutex_unlock(&htable->bucket_locks[hash]);
	return true;
}

struct tcp_ipv4_listener *query_tcp_listener_hashtable(struct tcp_ipv4_listener_htable *htable,
						       uint16_t port,
						       ipv4_address_t addr)
{
	uint32_t hash = calc_tcp_listener_hash(port, addr, htable);
	pthread_mutex_t *bucket_lock = &(htable->bucket_locks[hash]);
	pthread_mutex_lock(bucket_lock);
	struct tcp_ipv4_listener_node *bucket_node = htable->buckets[hash];

	while (bucket_node != NULL) {
		struct tcp_ipv4_listener *listener = bucket_node->listener;
		if (is_tcp_lstnr_match(listener, port, addr)) {
			retain_tcp_listener(listener);

			pthread_mutex_lock(&listener->lock);
			if (listener->state != TCP_LIS_CLOSED) {
				pthread_mutex_unlock(&listener->lock);
				pthread_mutex_unlock(bucket_lock);
				return listener;
			} else {
				pthread_mutex_unlock(&listener->lock);
				release_tcp_listener(listener);
			}
		}
		bucket_node = bucket_node->next;
	}
	pthread_mutex_unlock(bucket_lock);
	return NULL;
}

bool remove_from_tcp_listener_hashtable(struct tcp_ipv4_listener_htable *htable,
					struct tcp_ipv4_listener *listener)
{
	uint32_t hash = calc_tcp_listener_hash(listener->local_port, listener->local_addr, htable);

	pthread_mutex_t *lock = &(htable->bucket_locks[hash]);
	pthread_mutex_lock(lock);

	struct tcp_ipv4_listener_node *node = htable->buckets[hash];
	struct tcp_ipv4_listener_node *prev = NULL;
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
				ipv4_address_t ip,
				struct tcp_ipv4_listener_htable *htable)
{
	unsigned char data[6];
	data[0] = port & 0xFF;
	data[1] = (port >> 8) & 0xFF;
	memcpy(&data[2], ip, IPV4_ADDR_LEN);
	return hash_table(data, sizeof(data)) & (htable->buckets_amount - 1);
}

struct tcp_ipv4_listener_htable *create_tcp_ipv4_listener_htable(size_t size)
{
	// enforce only power of 2 sizes
	if (size == 0 || (size & (size - 1)) != 0)
		return NULL;

	struct tcp_ipv4_listener_htable *tcp_lstnr_htable = malloc(sizeof(*tcp_lstnr_htable));
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

	struct tcp_ipv4_listener_node **buckets = calloc(size, sizeof(*buckets));
	if (!buckets) {
		free(bckt_locks);
		free(tcp_lstnr_htable);
		return NULL;
	}

	tcp_lstnr_htable->buckets = buckets;
	return tcp_lstnr_htable;
}

bool is_tcp_lstnr_match(struct tcp_ipv4_listener *lstnr, uint16_t loc_port, ipv4_address_t loc_addr)
{
	return lstnr->local_port == loc_port &&
	       memcmp(lstnr->local_addr, loc_addr, IPV4_ADDR_LEN) == 0;
}
