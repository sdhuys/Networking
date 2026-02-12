#include "udp_hashtable.h"
#include "udp_socket.h"
#include <stdio.h>

bool add_to_udp_hashtable(struct udp_ipv4_sckt_htable_t *htable, struct udp_ipv4_socket_t *socket)
{
	uint32_t hash = calc_udp_hash(socket->local_port, socket->local_addr, htable);
	printf("%d => %d \n", socket->local_port, hash);

	pthread_mutex_lock(&htable->bucket_locks[hash]);

	struct udp_ipv4_sckt_htable_node_t *node = htable->buckets[hash];
	while (node != NULL) {
		if (node->socket->local_port == socket->local_port) {
			pthread_mutex_unlock(&htable->bucket_locks[hash]);
			return false;
		}
		node = node->next;
	}
	retain_udp_socket(socket);
	struct udp_ipv4_sckt_htable_node_t *new_node =
	    malloc(sizeof(struct udp_ipv4_sckt_htable_node_t));
	if (new_node == NULL)
		return NULL;

	new_node->socket = socket;
	new_node->next = htable->buckets[hash];
	htable->buckets[hash] = new_node;
	pthread_mutex_unlock(&htable->bucket_locks[hash]);
	return true;
}

struct udp_ipv4_socket_t *query_udp_hashtable(struct udp_ipv4_sckt_htable_t *htable,
					      uint16_t port,
					      ipv4_address addr)
{
	uint32_t hash = calc_udp_hash(port, addr, htable);
	struct udp_ipv4_sckt_htable_node_t *bucket_node = htable->buckets[hash];

	pthread_mutex_t *lock = &(htable->bucket_locks[hash]);
	pthread_mutex_lock(lock);
	while (bucket_node != NULL) {
		struct udp_ipv4_socket_t *socket = bucket_node->socket;
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

bool remove_from_udp_hashtable(struct udp_ipv4_sckt_htable_t *htable,
			       struct udp_ipv4_socket_t *socket)
{
	uint32_t hash = calc_udp_hash(socket->local_port, socket->local_addr, htable);

	pthread_mutex_t *lock = &(htable->bucket_locks[hash]);
	pthread_mutex_lock(lock);

	struct udp_ipv4_sckt_htable_node_t *node = htable->buckets[hash];
	struct udp_ipv4_sckt_htable_node_t *prev = NULL;
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

uint32_t calc_udp_hash(uint16_t port, ipv4_address ip, struct udp_ipv4_sckt_htable_t *htable)
{
	uint32_t ip_val;
	memcpy(&ip_val, ip, sizeof(uint32_t));
	uint32_t hash = port * GOLDEN_RATIO_32;
	hash = (hash ^ ip_val) * GOLDEN_RATIO_32;
	hash ^= hash >> 16;
	return (uint32_t)hash & (htable->buckets_amount - 1);
}