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
					    .try_get_pkt = NULL,
					    .send_pkt = NULL,
					    .close = tcp_close_listener};

pkt_result tcp_server_open_new_connection(struct tcp_ipv4_listener *lstnr,
					  struct pkt *pkt,
					  struct tcp_segment *seg)
{
	struct tcp_conn_id id = {.loc_port = lstnr->local_port,
				 .extern_port = ntohs(seg->header->src_port)};
	memcpy(id.extern_addr, pkt->src_ip, IPV4_ADDR_LEN);
	memcpy(id.loc_addr, pkt->dest_ip, IPV4_ADDR_LEN);

	struct tcp_ipv4_conn *conn = create_init_tcp_connection(&id, lstnr->tcp_layer);
	if (conn == NULL)
		return TCP_CONN_CREATION_ERROR;
	conn->lstnr = lstnr;
	server_init_tcp_connection(conn, seg);

	struct tcp_ipv4_conn_htable *htable =
	    ((struct tcp_context *)lstnr->tcp_layer->context)->socket_manager->tcp_ipv4_conn_htable;
	add_to_tcp_conn_hashtable(htable, conn);

	tcp_transition_to_state(conn, SYN_RECEIVED);
	tcp_syn_to_snd_buff(conn);

	return CONN_CREATED_SYN_ACK_TO_SND_BUFFER;
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
	
	listener->half_open_limit = TCP_LSTNR_HALF_OPENS_LIMIT;
	listener->local_port = port;
	memcpy(listener->local_addr, stack->local_address, IPV4_ADDR_LEN);
	listener->state = TCP_LIS_LISTEN;
	pthread_mutex_init(&listener->lock, NULL);
	listener->tcp_layer = stack->tcp_layer;
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
		release_tcp_conn(node->conn);
		free(node);
		node = next;
	}
	free(q);
}
