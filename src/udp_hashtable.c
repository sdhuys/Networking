#include "udp_hashtable.h"
#include "udp_socket.h"
#include <stdio.h>

bool add_to_udp_hashtable(struct udp_ipv4_sckt_htable *htable, struct udp_ipv4_socket *socket)
{
	uint32_t hash = calc_udp_hash(socket->local_port, socket->local_addr, htable);
	printf("%d => %d \n", socket->local_port, hash);

	pthread_mutex_lock(&htable->bucket_locks[hash]);

	struct udp_ipv4_sckt_htable_node *node = htable->buckets[hash];
	while (node != NULL) {
		if (node->socket->local_port == socket->local_port) {
			pthread_mutex_unlock(&htable->bucket_locks[hash]);
			return false;
		}
		node = node->next;
	}
	retain_udp_socket(socket);
	struct udp_ipv4_sckt_htable_node *new_node =
	    malloc(sizeof(struct udp_ipv4_sckt_htable_node));
	if (new_node == NULL)
		return NULL;

	new_node->socket = socket;
	new_node->next = htable->buckets[hash];
	htable->buckets[hash] = new_node;
	pthread_mutex_unlock(&htable->bucket_locks[hash]);
	return true;
}

struct udp_ipv4_socket *query_udp_hashtable(struct udp_ipv4_sckt_htable *htable,
					    uint16_t port,
					    ipv4_address addr)
{
	uint32_t hash = calc_udp_hash(port, addr, htable);
	struct udp_ipv4_sckt_htable_node *bucket_node = htable->buckets[hash];

	pthread_mutex_t *lock = &(htable->bucket_locks[hash]);
	pthread_mutex_lock(lock);
	while (bucket_node != NULL) {
		struct udp_ipv4_socket *socket = bucket_node->socket;
		if (socket->local_port == port && socket->state != UDP_CLOSED) {
			retain_udp_socket(socket);
			pthread_mutex_unlock(lock);
			return bucket_node->socket;
		}
		bucket_node = bucket_node->next;
	}
	pthread_mutex_unlock(lock);
	return NULL;
}

bool remove_from_udp_hashtable(struct udp_ipv4_sckt_htable *htable, struct udp_ipv4_socket *socket)
{
	uint32_t hash = calc_udp_hash(socket->local_port, socket->local_addr, htable);

	pthread_mutex_t *lock = &(htable->bucket_locks[hash]);
	pthread_mutex_lock(lock);

	struct udp_ipv4_sckt_htable_node *node = htable->buckets[hash];
	struct udp_ipv4_sckt_htable_node *prev = NULL;
	while (node != NULL) {
		if (node->socket == socket) {
			if (prev != NULL)
				prev->next = node->next;
			else
				htable->buckets[hash] = node->next;

			pthread_mutex_lock(&socket->lock);
			socket->state = UDP_CLOSED;
			pthread_mutex_unlock(&socket->lock);

			release_udp_socket(node->socket);
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

uint32_t calc_udp_hash(uint16_t port, ipv4_address ip, struct udp_ipv4_sckt_htable *htable)
{
	unsigned char data[6];
	data[0] = port & 0xFF;
	data[1] = (port >> 8) & 0xFF;
	memcpy(&data[2], ip, IPV4_ADDR_LEN);
	return hash_table(data, sizeof(data)) & (htable->buckets_amount - 1);
}

struct udp_ipv4_sckt_htable *create_udp_ipv4_sckt_htable(size_t size)
{
	// enforce only power of 2 sizes
	if (size == 0 || (size & (size - 1)) != 0)
		return NULL;

	struct udp_ipv4_sckt_htable *udp_htable = malloc(sizeof(*udp_htable));
	if (!udp_htable)
		return NULL;

	udp_htable->buckets_amount = size;

	pthread_mutex_t *bckt_locks = malloc(sizeof(pthread_mutex_t) * size);
	if (!bckt_locks) {
		free(udp_htable);
		return NULL;
	}

	for (size_t i = 0; i < size; i++)
		pthread_mutex_init(&bckt_locks[i], NULL);

	udp_htable->bucket_locks = bckt_locks;

	struct udp_ipv4_sckt_htable_node **buckets =
	    calloc(size, sizeof(struct udp_ipv4_sckt_htable_node *));
	if (!buckets) {
		free(bckt_locks);
		free(udp_htable);
		return NULL;
	}

	udp_htable->buckets = buckets;
	return udp_htable;
}
