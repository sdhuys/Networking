#include "socket_manager.h"
#include "send_request.h"
#include "stack.h"
#include "tcp_conn_socket.h"
#include "tcp_listener_htable.h"
#include "tcp_listener_socket.h"
#include "udp_hashtable.h"
#include "udp_socket.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

void notify_socket_readable_snd(struct socket_manager *mgr,
				void *sock,
				const struct socket_ops *ops)
{
	ops->retain(sock);
	ops->lock(sock);
	if (!ops->is_snd_queued(sock)) {
		ops->set_snd_queued(sock, true);
		ops->unlock(sock);
		struct socket_handle h = {.sock = sock, .ops = ops};
		enqueue_socket(mgr->send_down_sock_q, h);
	} else {
		ops->unlock(sock);
		ops->release(sock);
	}
}

// CONSUMER: Stack side (TX)
struct socket_handle dequeue_sock_snd_down_q(struct socket_manager *mgr)
{
	struct socket_h_q_node *node = dequeue_q_node(mgr->send_down_sock_q);
	struct socket_handle sock = {0};
	if (node) {
		sock = node->socket;
		sock.ops->lock(sock.sock);
		sock.ops->set_snd_queued(sock.sock, false);
		sock.ops->unlock(sock.sock);
		free(node);
	}

	return sock;
}

void release_socket(struct socket_handle sock)
{
	sock.ops->release(sock.sock);
}

struct socket_h_q_node *dequeue_q_node(struct socket_h_q *q)
{
	pthread_mutex_lock(&q->lock);
	if (!q->head) {
		pthread_mutex_unlock(&q->lock);
		return NULL;
	}

	struct socket_h_q_node *node = q->head;
	q->head = node->next;
	if (!q->head)
		q->tail = NULL;
	node->next = NULL;
	--q->len;
	pthread_mutex_unlock(&q->lock);
	return node;
}

void enqueue_socket(struct socket_h_q *q, struct socket_handle sock)
{
	struct socket_h_q_node *node = malloc(sizeof(*node));
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

int create_socket_handle(struct stack *stack,
			 socket_type type,
			 uint16_t local_port,
			 struct socket_handle *out)
{
	struct socket_manager *socket_manager = stack->sock_manager;

	switch (type) {
	case SOCK_UDP:
		struct udp_ipv4_socket *sock = create_udp_socket(local_port, stack);
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
		struct tcp_ipv4_listener *listener = create_tcp_listener(local_port, stack);
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

struct socket_handle create_conn_sock_h(struct tcp_ipv4_conn *conn)
{
	struct socket_handle h = {.sock = conn, .ops = &tcp_conn_ops};
	return h;
}
