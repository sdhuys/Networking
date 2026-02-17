#include "tcp_listener_socket.h"
#include "socket_manager.h"
#include "tcp_conn_htable.h"
#include "tcp_conn_socket.h"
#include "tcp_listener_htable.h"

const struct socket_ops_t tcp_listener_ops = {.is_snd_queued = NULL,
					      .set_snd_queued = NULL,
					      .retain = tcp_retain_listener,
					      .release = tcp_release_listener,
					      .write_to_snd_buffer = NULL,
					      .read_rcv_buffer = NULL,
					      .unlock = tcp_unlock_listner,
					      .lock = tcp_lock_listner,
					      .next_snd_pkt = NULL,
					      .send_pkt = NULL,
					      .close = tcp_close_listener};

struct tcp_ipv4_listener_t *create_tcp_listener(uint16_t port, struct stack_t *stack)
{
	struct tcp_ipv4_listener_t *listener = malloc(sizeof(struct tcp_ipv4_listener_t));
	if (listener == NULL)
		return NULL;

	listener->ready_q = create_ready_q();
	if (!listener->ready_q) {
		free(listener);
		return NULL;
	}
	listener->half_opens = create_tcp_ipv4_conn_htable(TCP_LSTNR_HALF_OPENS_BCKT_COUNT);
	listener->half_open_limit = TCP_LSTNR_HALF_OPENS_LIMIT;
	listener->local_port = port;
	memcpy(listener->local_addr, stack->local_address, IPV4_ADDR_LEN);
	listener->state = TCP_LIS_LISTEN;
	pthread_mutex_init(&listener->lock, NULL);
	listener->mgr = stack->sock_manager;
	return listener;
}

void retain_tcp_listener(struct tcp_ipv4_listener_t *listener)
{
	pthread_mutex_lock(&(listener->lock));
	listener->ref_count++;
	pthread_mutex_unlock(&(listener->lock));
}

void release_tcp_listener(struct tcp_ipv4_listener_t *listener)
{
	bool should_destroy = false;
	pthread_mutex_lock(&(listener->lock));

	listener->ref_count--;
	if (listener->ref_count <= 0)
		should_destroy = true;

	pthread_mutex_unlock(&(listener->lock));
	if (should_destroy)
		destroy_tcp_listener(listener);
}

void destroy_tcp_listener(struct tcp_ipv4_listener_t *listener)
{
	pthread_mutex_lock(&listener->lock);
	listener->state = TCP_LIS_CLOSED;
	destroy_ready_q(listener->ready_q);
	pthread_mutex_unlock(&listener->lock);
	pthread_mutex_destroy(&listener->lock);
	free(listener);
}

void tcp_release_listener(void *s)
{
	struct tcp_ipv4_listener_t *listener = (struct tcp_ipv4_listener_t *)s;
	release_tcp_listener(listener);
}

void tcp_retain_listener(void *s)
{
	struct tcp_ipv4_listener_t *listener = (struct tcp_ipv4_listener_t *)s;
	retain_tcp_listener(listener);
}

void tcp_close_listener(void *s)
{
	struct tcp_ipv4_listener_t *listener = (struct tcp_ipv4_listener_t *)s;
	remove_from_tcp_listener_hashtable(listener->mgr->tcp_ipv4_listener_htable, listener);
}

void tcp_lock_listner(void *s)
{
	struct tcp_ipv4_listener_t *listener = (struct tcp_ipv4_listener_t *)s;
	pthread_mutex_lock(&listener->lock);
}

void tcp_unlock_listner(void *s)
{
	struct tcp_ipv4_listener_t *listener = (struct tcp_ipv4_listener_t *)s;
	pthread_mutex_unlock(&listener->lock);
}

struct tcp_ipv4_conn_q_t *create_ready_q()
{
	struct tcp_ipv4_conn_q_t *q = malloc(sizeof(struct tcp_ipv4_conn_q_t));
	if (!q)
		return NULL;

	q->len = 0;
	q->head = NULL;
	q->tail = NULL;
	return q;
}

void destroy_ready_q(struct tcp_ipv4_conn_q_t *q)
{
	struct tcp_ipv4_conn_q_node_t *node = q->head;
	while (node) {
		struct tcp_ipv4_conn_q_node_t *next = node->next;
		destroy_tcp_conn(node->conn);
		free(node);
		node = next;
	}
	free(q);
}
