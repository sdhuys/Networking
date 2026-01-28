#include "udp.h"

pkt_result send_udp_down(struct nw_layer_t *self, struct pkt_t *packet)
{
	return NOT_IMPLEMENTED_YET;
}

pkt_result receive_udp_up(struct nw_layer_t *self, struct pkt_t *packet)
{
	struct udp_header_t *header = (struct udp_header_t *)(packet->data + packet->offset);
	if (!validate_checksum(header, packet))
		return UDP_CHECKSUM_ERROR;

	packet->offset += sizeof(struct udp_header_t);
	packet->len -= sizeof(struct udp_header_t);

	struct udp_context_t *context = (struct udp_context_t *)self->context;
	uint16_t dest_port = ntohs(header->dest_port);
	struct udp_ipv4_socket_t *socket = query_hashtable(context->socket_htable, dest_port);
	if (socket == NULL)
		return UDP_PORT_NO_LISTENER;
	return write_to_udp_socket(socket, packet);
}

pkt_result write_to_udp_socket(struct udp_ipv4_socket_t *socket, struct pkt_t *packet)
{
	if (socket->state == CLOSED)
		return UDP_SOCKET_CLOSED;
	// occasionally application could close socket in this windown between check and write
	// => release_socket will eventually destroy the socket anyway

	// add writing to ring buffer
	release_socket(socket);

	return SENT_UP_TO_APPLICATION;
}

struct udp_ipv4_socket_t *create_udp_socket(struct udp_context_t *context, uint16_t port)
{
	struct udp_ipv4_socket_t *socket = malloc(sizeof(struct udp_ipv4_socket_t));
	if (socket == NULL)
		return NULL;

	socket->local_port = port;
	socket->ref_count = 0;
	retain_socket(socket);
	// socket->rcv_buffer =
	// socket->snd_buffer =
	if (!add_to_hashtable(context->socket_htable, socket)) {
		release_socket(socket);
		return NULL;
	}
	socket->state = LISTENING;
	release_socket(socket);
	return socket;
}

void destroy_udp_socket(struct udp_ipv4_socket_t *socket)
{
	// free(socket->rcv_buffer);  // TODO: implement ring buffer destruction, pointer or not?
	// free(socket->snd_buffer);
	free(socket);
}

struct udp_ipv4_socket_t *query_hashtable(struct udp_ipv4_sckt_htable_t *htable, uint16_t dest_port)
{
	assert((htable->buckets_amount & (htable->buckets_amount - 1)) == 0);

	uint32_t hash = calc_hash(dest_port, htable);
	struct udp_ipv4_sckt_htable_node_t *bucket_node = htable->buckets[hash];

	pthread_rwlock_t *lock = &(htable->bucket_locks[hash]);
	pthread_rwlock_rdlock(lock);
	while (bucket_node != NULL) {
		if (bucket_node->socket->local_port == dest_port &&
		    bucket_node->socket->state != CLOSED) {
			retain_socket(bucket_node->socket);
			pthread_rwlock_unlock(lock);
			return bucket_node->socket;
		}
		bucket_node = bucket_node->next;
	}
	pthread_rwlock_unlock(lock);
	return NULL;
}

bool remove_from_hashtable(struct udp_ipv4_sckt_htable_t *htable, struct udp_ipv4_socket_t *socket)
{
	uint32_t hash = calc_hash(socket->local_port, htable);

	pthread_rwlock_t *lock = &(htable->bucket_locks[hash]);
	pthread_rwlock_wrlock(lock);

	struct udp_ipv4_sckt_htable_node_t *node = htable->buckets[hash];
	struct udp_ipv4_sckt_htable_node_t *prev = NULL;
	while (node != NULL) {
		if (node->socket == socket) {
			if (prev != NULL)
				prev->next = node->next;
			else
				htable->buckets[hash] = node->next;
			socket->state = CLOSED;
			release_socket(node->socket);
			free(node);
			pthread_rwlock_unlock(lock);
			return true;
		}
		prev = node;
		node = node->next;
	}
	pthread_rwlock_unlock(lock);
	return false;
}

bool add_to_hashtable(struct udp_ipv4_sckt_htable_t *htable, struct udp_ipv4_socket_t *socket)
{
	uint32_t hash = calc_hash(socket->local_port, htable);

	pthread_rwlock_t *lock = &(htable->bucket_locks[hash]);
	pthread_rwlock_wrlock(lock);

	struct udp_ipv4_sckt_htable_node_t *node = htable->buckets[hash];
	while (node != NULL) {
		if (node->socket->local_port == socket->local_port) {
			pthread_rwlock_unlock(lock);
			return false;
		}
		node = node->next;
	}
	retain_socket(socket);
	struct udp_ipv4_sckt_htable_node_t *new_node =
	    malloc(sizeof(struct udp_ipv4_sckt_htable_node_t));
	if (new_node == NULL)
		return NULL;
		
	new_node->socket = socket;
	new_node->next = htable->buckets[hash];
	htable->buckets[hash] = new_node;
	pthread_rwlock_unlock(lock);
	return true;
}

void retain_socket(struct udp_ipv4_socket_t *socket)
{
	socket->ref_count++;
}

void release_socket(struct udp_ipv4_socket_t *socket)
{
	if (--socket->ref_count <= 0)
		destroy_udp_socket(socket);
}

uint32_t calc_hash(uint16_t port, struct udp_ipv4_sckt_htable_t *htable)
{
	return (uint32_t)(port * GOLDEN_RATIO_32) & (htable->buckets_amount - 1);
}

bool validate_checksum(struct udp_header_t *header, struct pkt_t *packet)
{
	// no checksum used
	if (header->checksum == 0)
		return true;

	struct ipv4_pseudo_header_t *pseudo_h = (struct ipv4_pseudo_header_t *)&packet->src_ip;
	pseudo_h->len = header->length;
	pseudo_h->padding = 0;
	pseudo_h->protocol = UDP;
	uint16_t udp_length = ntohs(header->length);

	struct checksum_chunk chunks[2] = {
	    {.data = packet->data + packet->offset, .len = udp_length},
	    {.data = pseudo_h, .len = sizeof(struct ipv4_pseudo_header_t)}};
	uint16_t checksum = calc_checksum(chunks, 2);
	pseudo_h->len = udp_length;
	return checksum == 0;
}