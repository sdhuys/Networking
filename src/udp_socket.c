#include "udp_socket.h"
#include "udp_hashtable.h"
#include <stdio.h>

const struct socket_ops udp_socket_ops = {.is_snd_queued = udp_is_snd_queued,
					  .set_snd_queued = udp_set_snd_queued,
					  .retain = udp_retain,
					  .release = udp_release,
					  .write_to_snd_buffer = udp_write_to_snd_buffer,
					  .read_rcv_buffer = udp_read_rcv_buffer,
					  .read_rcv_buffer_from = udp_read_rcv_buffer_from,
					  .unlock = unlock_socket,
					  .lock = lock_socket,
					  .snd_ready = udp_send_ready,
					  .send_pkt = udp_send_pkt,
					  .close = udp_close_sock};

struct udp_ipv4_socket *create_udp_socket(uint16_t port, struct stack *stack)
{
	struct udp_ipv4_socket *socket = malloc(sizeof(struct udp_ipv4_socket));
	if (socket == NULL)
		return NULL;

	socket->local_port = port;
	memcpy(socket->local_addr, stack->local_address, IPV4_ADDR_LEN);
	socket->ref_count = 0;
	socket->queued_for_snd = false;
	struct pkt_ring_buffer *rcv_b = create_init_pkt_ring_buffer(UDP_RING_BUFF_SIZE);
	struct pkt_ring_buffer *snd_b = create_init_pkt_ring_buffer(UDP_RING_BUFF_SIZE);
	socket->rcv_buffer = rcv_b;
	socket->snd_buffer = snd_b;
	pthread_mutex_init(&socket->lock, NULL);
	socket->state = UDP_LISTEN;
	return socket;
}

void broadcast_udp_rcv_readable(struct udp_ipv4_socket *socket)
{
	pthread_cond_broadcast(&socket->rcv_buffer->cond);
}

void destroy_udp_socket(struct udp_ipv4_socket *socket)
{
	pthread_mutex_destroy(&socket->lock);
	destroy_pkt_ring_buffer(socket->rcv_buffer);
	destroy_pkt_ring_buffer(socket->snd_buffer);
	free(socket);
	printf("UDP SOCK DESTROYED \n");
}

void retain_udp_socket(struct udp_ipv4_socket *socket)
{
	pthread_mutex_t *lock = &(socket->lock);
	pthread_mutex_lock(lock);
	socket->ref_count++;
	pthread_mutex_unlock(lock);
}

void release_udp_socket(struct udp_ipv4_socket *socket)
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

pkt_result write_up_to_rcv_buffer(struct udp_ipv4_socket *socket, struct pkt *packet)
{
	pthread_mutex_lock(&(socket->lock));
	if (socket->state == UDP_CLOSED) {
		pthread_mutex_unlock(&(socket->lock));
		return UDP_SOCKET_CLOSED;
	}
	pthread_mutex_unlock(&(socket->lock));

	if (!write_to_pkt_buffer(socket->rcv_buffer, packet))
		return RING_BUFFER_FULL;

	broadcast_udp_rcv_readable(socket);
	return UDP_WRITTEN_TO_RCV_BUFF;
}

// socket handle operations (app side)
bool udp_is_snd_queued(void *s)
{
	return ((struct udp_ipv4_socket *)s)->queued_for_snd;
}

void udp_set_snd_queued(void *s, bool v)
{
	((struct udp_ipv4_socket *)s)->queued_for_snd = v;
}

void udp_retain(void *s)
{
	retain_udp_socket((struct udp_ipv4_socket *)s);
}

void udp_release(void *s)
{
	release_udp_socket((struct udp_ipv4_socket *)s);
}

// return false doesn't differentiate between free packet pool empty and ring buffer full
bool udp_write_to_snd_buffer(struct stack *stack, void *s, struct send_request req)
{
	struct udp_ipv4_socket *socket = (struct udp_ipv4_socket *)s;
	pthread_mutex_lock(&socket->lock);

	if (socket->state == UDP_CLOSED) {
		pthread_mutex_unlock(&socket->lock);
		return false;
	}
	pthread_mutex_unlock(&socket->lock);

	struct pkt_ring_buffer *buffer = socket->snd_buffer;

	printf("UDP SOCKET ALLOCATING \n");
	struct pkt *packet = allocate_pkt(); // caller ownership
	if (packet == NULL)
		return false;

	packet->len = req.len;
	memcpy(packet->src_ip, socket->local_addr, IPV4_ADDR_LEN);
	memcpy(packet->dest_ip, req.dest_ip, IPV4_ADDR_LEN);
	packet->dest_port = req.dest_port;
	packet->src_port = socket->local_port;
	packet->offset = PKT_SIZE - req.len;
	packet->protocol = P_UDP;
	memcpy((packet->data + packet->offset), req.data, req.len);
	packet->len += sizeof(struct udp_header);
	packet->offset -= sizeof(struct udp_header);

	if (!write_to_pkt_buffer(buffer, packet)) {
		release_pkt(packet); // failure, buffer releases ownership
		return false;
	}
	notify_socket_readable_snd(stack->sock_manager, socket, &udp_socket_ops);
	return true;
}

int udp_read_rcv_buffer(void *s, size_t len, unsigned char *buff)
{
	struct udp_ipv4_socket *socket = (struct udp_ipv4_socket *)s;
	struct pkt_ring_buffer *rcv_buffer = socket->rcv_buffer;
	struct pkt *pkt = read_pkt_buffer_blocking(rcv_buffer);
	size_t copy_len = pkt->len > len ? len : pkt->len;
	memcpy(buff, (pkt->data + pkt->offset), copy_len);
	printf("APP SOCKET RELEASING \n");
	release_pkt(pkt);
	return copy_len;
}

int udp_read_rcv_buffer_from(
    void *s, size_t len, unsigned char *buff, ipv4_address_t addr_out, uint16_t *port_out)
{
	struct udp_ipv4_socket *socket = (struct udp_ipv4_socket *)s;
	struct pkt_ring_buffer *rcv_buffer = socket->rcv_buffer;
	struct pkt *pkt = read_pkt_buffer_blocking(rcv_buffer);
	size_t copy_len = pkt->len > len ? len : pkt->len;
	memcpy(buff, (pkt->data + pkt->offset), copy_len);
	printf("APP SOCKET RELEASING \n");
	release_pkt(pkt);
	memcpy(addr_out, pkt->src_ip, IPV4_ADDR_LEN);
	memcpy(port_out, &pkt->src_port, sizeof(uint16_t));
	return copy_len;
}

void lock_socket(void *s)
{
	struct udp_ipv4_socket *socket = (struct udp_ipv4_socket *)s;
	pthread_mutex_lock(&socket->lock);
}

void unlock_socket(void *s)
{
	struct udp_ipv4_socket *socket = (struct udp_ipv4_socket *)s;
	pthread_mutex_unlock(&socket->lock);
}

bool udp_send_ready(void *s)
{
	struct udp_ipv4_socket *sock = s;
	if (pkt_buffer_empty(sock->snd_buffer))
		return false;
	return true;
}

pkt_result udp_send_pkt(struct stack *stack, void *s)
{
	struct udp_ipv4_socket *sock = s;
	struct pkt *p = read_pkt_buffer(sock->snd_buffer);
	if (!p) {
		printf("TRYING TO SEND WHEN NOTHING TO SEND, SHOULD NOT HAPPEN! \n");
		abort();
	}
	return stack->udp_layer->send_down(stack->udp_layer, p);
}

void udp_close_sock(struct stack *stack, void *s)
{
	struct udp_ipv4_socket *sock = (struct udp_ipv4_socket *)s;
	remove_from_udp_hashtable(stack->sock_manager->udp_ipv4_sckt_htable, sock);
}