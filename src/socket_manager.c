#include "socket_manager.h"
#include <assert.h>
#include <stdio.h>

void notify_socket_readable_snd(struct socket_manager_t *mgr,
				void *sock,
				const struct socket_ops_t *ops)
{
	ops->lock(sock);
	if (!ops->is_snd_queued(sock)) {
		ops->set_snd_queued(sock, true);
		ops->unlock(sock);
		ops->retain(sock);
		struct socket_handle_t h = {.sock = sock, .ops = ops};
		enqueue_socket(mgr->send_down_sock_q, h);
	} else {
		ops->unlock(sock);
	}
}

// CONSUMER: Stack side (TX)
struct socket_handle_t dequeue_sock_snd_down_q(struct socket_manager_t *mgr)
{
	struct socket_h_q_node_t *node = dequeue_q_node(mgr->send_down_sock_q);
	struct socket_handle_t sock = {0};
	if (node) {
		sock = node->socket;
		free(node);
	}
	return sock;
}

void release_socket_from_queue(struct socket_handle_t sock)
{
	sock.ops->lock(sock.sock);

	sock.ops->set_snd_queued(sock.sock, false);
	sock.ops->unlock(sock.sock);
	sock.ops->release(sock.sock);
}

struct socket_h_q_node_t *dequeue_q_node(struct socket_h_q_t *q)
{
	pthread_mutex_lock(&q->lock);
	if (!q->head) {
		pthread_mutex_unlock(&q->lock);
		return NULL;
	}

	struct socket_h_q_node_t *node = q->head;
	q->head = node->next;
	if (!q->head)
		q->tail = NULL;
	node->next = NULL;
	--q->len;
	pthread_mutex_unlock(&q->lock);
	return node;
}

void enqueue_socket(struct socket_h_q_t *q, struct socket_handle_t sock)
{
	struct socket_h_q_node_t *node = malloc(sizeof(*node));
	if (!node)
		return;

	node->socket = sock;
	node->next = NULL;

	pthread_mutex_lock(&q->lock);
	if (!q->head) {
		q->head = node;
		q->tail = node;
	} else {
		q->tail->next = node;
		q->tail = node;
	}
	if (q->len++ == 0)
		pthread_cond_broadcast(&q->cond);
	pthread_mutex_unlock(&q->lock);
}

int create_socket_handle(struct stack_t *stack,
			 socket_type_t type,
			 uint16_t local_port,
			 struct socket_handle_t *out)
{
	struct socket_manager_t *socket_manager = stack->sock_manager;

	switch (type) {
	case SOCK_UDP:
		struct udp_ipv4_socket_t *sock = create_udp_socket(local_port, stack);
		if (!sock)
			return -2; // ALLOCATION FAILURE
		retain_udp_socket(sock);
		out->sock = sock;
		out->ops = &udp_socket_ops;
		if (!add_to_udp_hashtable(socket_manager->udp_ipv4_sckt_htable, sock)) {
			release_udp_socket(sock);
			return -3; // PORT ALREADY IN USE
		}
		break;

	case SOCK_TCP:
		struct tcp_ipv4_listener_t *listener = create_tcp_listener(local_port, stack);
		if (!listener)
			return -2; // ALLOCATION FAILURE
		retain_tcp_listener(listener);
		out->sock = listener;
		out->ops = &tcp_listener_ops;
		if (!add_to_tcp_listener_hashtable(socket_manager->tcp_ipv4_listener_htable,
						   listener)) {
			release_tcp_listener(listener);
			return -3; // PORT ALREADY IN USE
		}
		break;
	}
	return 0;
}
