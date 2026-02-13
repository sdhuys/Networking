#include "socket_manager.h"
#include <stdio.h>

void notify_socket_readable_rcv(struct socket_manager_t *mgr,
				void *sock,
				const struct socket_ops_t *ops,
				socket_type_t type)
{
	ops->lock(sock);
	if (!ops->is_rcv_queued(sock)) {
		ops->set_rcv_queued(sock, true);
		ops->unlock(sock);
		ops->retain(sock);
		struct socket_handle_t h = {.sock = sock, .type = type, .ops = ops};
		enqueue_socket(mgr->receive_up_sock_q, h);
	} else {
		ops->unlock(sock);
	}
}

void notify_socket_readable_snd(struct socket_manager_t *mgr,
				void *sock,
				const struct socket_ops_t *ops,
				socket_type_t type)
{
	ops->lock(sock);
	if (!ops->is_snd_queued(sock)) {
		ops->set_snd_queued(sock, true);
		ops->unlock(sock);
		ops->retain(sock);
		struct socket_handle_t h = {.sock = sock, .type = type, .ops = ops};
		enqueue_socket(mgr->send_down_sock_q, h);
	} else {
		ops->unlock(sock);
	}
}

// CONSUMER: Application side (RX)
struct socket_handle_t dequeue_readable_socket(struct socket_manager_t *mgr)
{
	struct socket_h_q_node_t *node = dequeue_socket(mgr->receive_up_sock_q);
	struct socket_handle_t sock = {0};
	if (node) {
		sock = node->socket;
		free(node);
	}
	return sock;
}

// CONSUMER: Stack side (TX)
struct socket_handle_t dequeue_writable_socket(struct socket_manager_t *mgr)
{
	struct socket_h_q_node_t *node = dequeue_socket(mgr->send_down_sock_q);
	struct socket_handle_t sock = {0};
	if (node) {
		sock = node->socket;
		free(node);
	}
	return sock;
}

void release_socket_from_queue(struct socket_handle_t sock, bool rx)
{
	sock.ops->lock(sock.sock);
	if (rx)
		sock.ops->set_rcv_queued(sock.sock, false);
	else
		sock.ops->set_snd_queued(sock.sock, false);
	sock.ops->unlock(sock.sock);
	sock.ops->release(sock.sock);
}

struct socket_h_q_node_t *dequeue_socket(struct socket_h_q_t *q)
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