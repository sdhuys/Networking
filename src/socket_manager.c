#include "socket_manager.h"

void notify_socket_readable_rcv(struct socket_manager_t *mgr, struct socket_handle_t sock_h)
{
	if (!sock_h.ops->is_rcv_queued(sock_h.sock)) {
		sock_h.ops->set_rcv_queued(sock_h.sock, true);
		sock_h.ops->unlock(sock_h.sock); // UNLOCK FIRST
		sock_h.ops->retain(sock_h.sock);
		enqueue_socket(mgr->receive_up_sock_q, sock_h);
	}
}

void notify_socket_readable_snd(struct socket_manager_t *mgr, struct socket_handle_t sock_h)
{
	if (!sock_h.ops->is_snd_queued(sock_h.sock)) {
		sock_h.ops->set_snd_queued(sock_h.sock, true);
		sock_h.ops->unlock(sock_h.sock); // UNLOCK FIRST
		sock_h.ops->retain(sock_h.sock);
		enqueue_socket(mgr->send_down_sock_q, sock_h);
	}
}

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

void release_socket_from_queue(struct socket_handle_t sock, bool rx)
{
	if (rx)
		sock.ops->set_rcv_queued(sock.sock, false);
	else
		sock.ops->set_snd_queued(sock.sock, false);

	sock.ops->release(sock.sock);
}

struct socket_h_q_node_t *dequeue_socket(struct socket_h_q_t *q)
{
	if (!q->head)
		return NULL;

	struct socket_h_q_node_t *node = q->head;
	q->head = node->next;
	if (!q->head)
		q->tail = NULL;
	node->next = NULL;
	return node;
}

void enqueue_socket(struct socket_h_q_t *q, struct socket_handle_t sock)
{
	struct socket_h_q_node_t *node = malloc(sizeof(*node));
	if (!node)
		return;

	node->socket = sock;
	node->next = NULL;

	if (!q->head) {
		q->head = node;
		q->tail = node;
	} else {
		q->tail->next = node;
		q->tail = node;
	}
}