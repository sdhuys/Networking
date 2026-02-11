#include "udp_socket.h"
#include <stdio.h>

const struct socket_ops_t udp_socket_ops = {.is_rcv_queued = udp_is_rcv_queued,
					    .set_rcv_queued = udp_set_rcv_queued,
					    .is_snd_queued = udp_is_snd_queued,
					    .set_snd_queued = udp_set_snd_queued,
					    .retain = udp_retain,
					    .release = udp_release,
					    .write_to_snd_buffer = udp_write_to_snd_buffer,
					    .read_rcv_buffer = udp_read_rcv_buffer,
					    .unlock = unlock_socket,
					    .lock = lock_socket};

struct udp_ipv4_socket_t *create_udp_socket(uint16_t port)
{
	struct udp_ipv4_socket_t *socket = malloc(sizeof(struct udp_ipv4_socket_t));
	if (socket == NULL)
		return NULL;

	socket->local_port = port;
	socket->ref_count = 0;
	socket->queued_for_rcv = false;
	socket->queued_for_snd = false;
	struct ring_buffer_t *rcv_b = create_init_ring_buffer();
	struct ring_buffer_t *snd_b = create_init_ring_buffer();
	socket->rcv_buffer = rcv_b;
	socket->snd_buffer = snd_b;
	pthread_mutex_init(&socket->lock, NULL);
	socket->state = LISTENING;
	socket->mgr = NULL; // set by app_socket_open()
	return socket;
}

void destroy_udp_socket(struct udp_ipv4_socket_t *socket)
{
	pthread_mutex_destroy(&socket->lock);
	free(socket->rcv_buffer);
	free(socket->snd_buffer);
	free(socket);
}

void retain_udp_socket(struct udp_ipv4_socket_t *socket)
{
	pthread_mutex_t *lock = &(socket->lock);
	pthread_mutex_lock(lock);
	socket->ref_count++;
	pthread_mutex_unlock(lock);
}

void release_udp_socket(struct udp_ipv4_socket_t *socket)
{
	bool should_destroy = false;
	pthread_mutex_t *lock = &(socket->lock);
	pthread_mutex_lock(lock);

	socket->ref_count--;
	if (socket->ref_count <= 0)
		should_destroy = true;

	pthread_mutex_unlock(lock);
	if (should_destroy)
		destroy_udp_socket(socket);
}

pkt_result write_up_to_rcv_buffer(struct udp_ipv4_socket_t *socket, struct pkt_t *packet)
{
	pthread_mutex_lock(&(socket->lock));
	if (socket->state == CLOSED) {
		pthread_mutex_unlock(&(socket->lock));
		return UDP_SOCKET_CLOSED;
	}
	pthread_mutex_unlock(&(socket->lock));

	if (!write_to_buffer(socket->rcv_buffer, packet))
		return RING_BUFFER_FULL;

	notify_socket_readable_rcv(socket->mgr, socket, &udp_socket_ops, SOCK_UDP);
	return SENT_UP_TO_APPLICATION;
}

// socket handle operations (app side)
bool udp_is_rcv_queued(void *s)
{
	return ((struct udp_ipv4_socket_t *)s)->queued_for_rcv;
}

void udp_set_rcv_queued(void *s, bool v)
{
	((struct udp_ipv4_socket_t *)s)->queued_for_rcv = v;
}

bool udp_is_snd_queued(void *s)
{
	return ((struct udp_ipv4_socket_t *)s)->queued_for_snd;
}

void udp_set_snd_queued(void *s, bool v)
{
	((struct udp_ipv4_socket_t *)s)->queued_for_snd = v;
}

void udp_retain(void *s)
{
	retain_udp_socket((struct udp_ipv4_socket_t *)s);
}

void udp_release(void *s)
{
	release_udp_socket((struct udp_ipv4_socket_t *)s);
}

// return false doesn't differentiate between free packet pool empty and ring buffer full
bool udp_write_to_snd_buffer(void *s, struct send_request_t req)
{
	struct udp_ipv4_socket_t *socket = (struct udp_ipv4_socket_t *)s;
	pthread_mutex_lock(&socket->lock);

	if (socket->state == CLOSED) {
		pthread_mutex_unlock(&socket->lock);
		return false;
	}
	pthread_mutex_unlock(&socket->lock);

	struct ring_buffer_t *buffer = socket->snd_buffer;

	printf("UDP SOCKET ALLOCATING \n");
	struct pkt_t *packet = allocate_pkt(); // caller ownership
	if (packet == NULL)
		return false;

	packet->len = req.len;
	memcpy(packet->dest_ip, req.dest_ip, IPV4_ADDR_LEN);
	packet->dest_port = req.dest_port;
	packet->src_port = socket->local_port;
	packet->offset = MAX_ETH_FRAME_SIZE - req.len - sizeof(struct udp_header_t);
	packet->protocol = P_UDP;
	memcpy((packet->data + packet->offset), req.data, req.len);

	if (!write_to_buffer(buffer, packet)) {
		release_pkt(packet); // failure, buffer releases ownership
		return false;
	}
	notify_socket_readable_snd(socket->mgr, socket, &udp_socket_ops, SOCK_UDP);
	return true;
}

struct pkt_t *udp_read_rcv_buffer(void *s)
{
	struct udp_ipv4_socket_t *socket = (struct udp_ipv4_socket_t *)s;
	struct ring_buffer_t *rcv_buffer = socket->rcv_buffer;
	struct pkt_t *pkt = read_buffer(rcv_buffer);
	return pkt;
}

void lock_socket(void *s)
{
	struct udp_ipv4_socket_t *socket = (struct udp_ipv4_socket_t *)s;
	pthread_mutex_lock(&socket->lock);
}

void unlock_socket(void *s)
{
	struct udp_ipv4_socket_t *socket = (struct udp_ipv4_socket_t *)s;
	pthread_mutex_unlock(&socket->lock);
}