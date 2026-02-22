#include "tcp_listener_socket.h"
#include "time.h"

#define TCP_LSTNR_HALF_OPENS_BCKT_COUNT 1024
#define TCP_LSTNR_HALF_OPENS_LIMIT 256

const struct socket_ops tcp_listener_ops = {.is_snd_queued = NULL,
					    .set_snd_queued = NULL,
					    .retain = tcp_retain_listener,
					    .release = tcp_release_listener,
					    .write_to_snd_buffer = NULL,
					    .read_rcv_buffer = NULL,
					    .unlock = tcp_unlock_listener,
					    .lock = tcp_lock_listener,
					    .next_snd_pkt = NULL,
					    .send_pkt = NULL,
					    .close = tcp_close_listener};

pkt_result tcp_open_new_connection(struct tcp_ipv4_listener *listener, struct tcp_segment *seg)
{
	uint32_t iss;
	uint32_t ack = seg->header->seq_num + seg_len(seg);
	iss = generate_random_iss();
	struct tcp_ipv4_conn *conn = create_tcp_connection(seg, iss);
	if (conn == NULL)
		return TCP_CONN_CREATION_ERROR;
	// add connection to listener's half-open htable
	// send SYN ACK
}

pkt_result half_open_check_ack(struct tcp_segment *seg,
			       struct tcp_ipv4_conn *half_open,
			       struct tcp_ipv4_listener *lstnr)
{
	return NOT_IMPLEMENTED_YET;
}

struct tcp_ipv4_listener *create_tcp_listener(uint16_t port, struct stack *stack)
{
	struct tcp_ipv4_listener *listener = malloc(sizeof(struct tcp_ipv4_listener));
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
	return listener;
}

void retain_tcp_listener(struct tcp_ipv4_listener *listener)
{
	pthread_mutex_lock(&(listener->lock));
	listener->ref_count++;
	pthread_mutex_unlock(&(listener->lock));
}

void release_tcp_listener(struct tcp_ipv4_listener *listener)
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

void destroy_tcp_listener(struct tcp_ipv4_listener *listener)
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
	struct tcp_ipv4_listener *listener = (struct tcp_ipv4_listener *)s;
	release_tcp_listener(listener);
}

void tcp_retain_listener(void *s)
{
	struct tcp_ipv4_listener *listener = (struct tcp_ipv4_listener *)s;
	retain_tcp_listener(listener);
}

void tcp_close_listener(struct stack *stack, void *s)
{
	struct tcp_ipv4_listener *listener = (struct tcp_ipv4_listener *)s;
	remove_from_tcp_listener_hashtable(stack->sock_manager->tcp_ipv4_listener_htable, listener);
}

void tcp_lock_listener(void *s)
{
	struct tcp_ipv4_listener *listener = (struct tcp_ipv4_listener *)s;
	pthread_mutex_lock(&listener->lock);
}

void tcp_unlock_listener(void *s)
{
	struct tcp_ipv4_listener *listener = (struct tcp_ipv4_listener *)s;
	pthread_mutex_unlock(&listener->lock);
}

struct tcp_ipv4_conn_q *create_ready_q()
{
	struct tcp_ipv4_conn_q *q = malloc(sizeof(struct tcp_ipv4_conn_q));
	if (!q)
		return NULL;

	q->len = 0;
	q->head = NULL;
	q->tail = NULL;
	return q;
}

void destroy_ready_q(struct tcp_ipv4_conn_q *q)
{
	struct tcp_ipv4_conn_q_node *node = q->head;
	while (node) {
		struct tcp_ipv4_conn_q_node *next = node->next;
		destroy_tcp_conn(node->conn);
		free(node);
		node = next;
	}
	free(q);
}
