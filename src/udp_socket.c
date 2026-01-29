#include "udp_socket.h"
#include <stdio.h>

const struct socket_ops_t udp_socket_ops = {.is_rcv_queued = udp_is_rcv_queued,
					    .set_rcv_queued = udp_set_rcv_queued,
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
	return socket;
}

struct ring_buffer_t *create_init_ring_buffer()
{
	struct ring_buffer_t *buff = malloc(sizeof(struct ring_buffer_t));
	if (buff == NULL)
		return NULL;

	buff->head = 0;
	buff->tail = 0;
	return buff;
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

pkt_result write_up_to_rcv_buffer(struct socket_manager_t *socket_manager,
				  struct udp_ipv4_socket_t *socket,
				  struct pkt_t *packet)
{
	pthread_mutex_t *lock = &(socket->lock);
	pthread_mutex_lock(lock);

	if (socket->state == CLOSED) {
		pthread_mutex_unlock(lock);
		return UDP_SOCKET_CLOSED;
	}

	if (!write_to_buffer(socket->rcv_buffer, packet)) {
		return RING_BUFFER_FULL;
		pthread_mutex_unlock(lock);
	}

	struct socket_handle_t sock_h = create_udp_socket_handle(socket);
	notify_socket_readable_rcv(socket_manager, sock_h);

	pthread_mutex_unlock(lock);
	return SENT_UP_TO_APPLICATION;
}

// should only be called while socket owning the buffer is under lock
bool write_to_buffer(struct ring_buffer_t *buff, struct pkt_t *packet)
{
	uint32_t next_head = (buff->head + 1) % RING_BUFF_SIZE;
	if (next_head == buff->tail)
		return false;

	buff->packets[buff->head] = packet;
	buff->head = next_head;
	return true;
}

// should only be called while socket owning the buffer is under lock
struct pkt_t *read_buffer(struct ring_buffer_t *buff)
{
	if (buff->head == buff->tail)
		return NULL;

	struct pkt_t *pkt = buff->packets[buff->tail];
	buff->tail = (buff->tail + 1) % RING_BUFF_SIZE;
	return pkt;
}

struct socket_handle_t create_udp_socket_handle(struct udp_ipv4_socket_t *socket)
{
	struct socket_handle_t handle;
	handle.sock = socket;
	handle.type = SOCK_UDP;
	handle.ops = &udp_socket_ops;
	return handle;
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

	pthread_mutex_t *soc_lock = &socket->lock;
	pthread_mutex_lock(soc_lock);

	if (socket->state == CLOSED)
		return false;

	struct ring_buffer_t *buffer = socket->snd_buffer;

	struct pkt_t *packet = allocate_pkt(); // caller ownership
	if (packet == NULL)
		return false;

	packet->data = req.data;
	packet->len = req.len;
	memcpy(packet->dest_ip, req.dest_ip, IPV4_ADDR_LEN);
	packet->dest_port = req.dest_port;
	packet->src_port = socket->local_port;
	packet->offset = MAX_ETH_FRAME_SIZE - req.len - sizeof(struct udp_header_t);
	packet->protocol = P_UDP;

	retain_pkt(packet); // increment for the buffer's ownership
	if (!write_to_buffer(buffer, packet)) {
		release_pkt(packet); // failure, buffer releases ownership
		release_pkt(packet); // caller releases ownership too
		pthread_mutex_unlock(soc_lock);
		return false;
	}

	// notify_socket_readable_snd(); NEED ACCESS TO SOCK_MANAGER, MAKE GLOBAL?
	//  OR store in socket struct?
	release_pkt(packet); // caller releases ownership

	pthread_mutex_unlock(soc_lock);
	return true;
}

struct pkt_t *udp_read_rcv_buffer(void *s)
{
	struct udp_ipv4_socket_t *socket = (struct udp_ipv4_socket_t *)s;

	pthread_mutex_t *lock = &(socket->lock);
	pthread_mutex_lock(lock);
	struct ring_buffer_t *rcv_buffer = socket->rcv_buffer;
	struct pkt_t *pkt = read_buffer(rcv_buffer);
	pthread_mutex_unlock(lock);
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