#include "tcp_listener_socket.h"
#include "container_of.h"
#include "nw_layer.h"
#include "pkt.h"
#include "queue.h"
#include "routing_table.h"
#include "socket_manager.h"
#include "stack.h"
#include "tcp.h"
#include "tcp_conn_htable.h"
#include "tcp_conn_socket.h"
#include "tcp_listener_htable.h"
#include "tcp_segment.h"
#include "time.h"
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>

#define TCP_LSTNR_HALF_OPENS_BCKT_COUNT 1024
#define TCP_LSTNR_HALF_OPENS_LIMIT 256

const struct socket_ops tcp_listener_ops = {.is_snd_queued = NULL,
					    .set_snd_queued = NULL,
					    .retain = tcp_retain_listener,
					    .release = tcp_release_listener,
					    .write_to_snd_buffer = NULL,
					    .read_rcv_buffer = NULL,
					    .unlock = NULL,
					    .lock = NULL,
					    .try_get_pkt = NULL,
					    .send_pkt = NULL,
					    .close = tcp_close_listener,
					    .accept = tcp_lstnr_accept_conn,
					    .end_snd = NULL};

pkt_result tcp_server_open_new_connection(struct tcp_ipv4_listener *lstnr,
					  struct pkt *pkt,
					  struct tcp_segment *seg)
{
	struct tcp_conn_id id = {.loc_port = lstnr->local_port,
				 .extern_port = ntohs(seg->header->src_port)};
	memcpy(id.extern_addr, pkt->src_ip, IPV4_ADDR_LEN);
	memcpy(id.loc_addr, pkt->dest_ip, IPV4_ADDR_LEN);

	struct tcp_context *ctx = (struct tcp_context *)lstnr->tcp_layer->context;
	struct route *route;
	get_route(ctx->routing_tbl, id.extern_addr, &route); // set to NULL if no route

	struct tcp_ipv4_conn *conn = create_init_tcp_connection(&id, lstnr->tcp_layer, route);
	if (conn == NULL)
		return TCP_CONN_CREATION_ERROR;

	retain_tcp_conn(conn);
	conn->lstnr = lstnr;
	retain_tcp_listener(lstnr);
	server_init_tcp_connection(conn, seg);

	struct tcp_ipv4_conn_htable *htable =
	    ((struct tcp_context *)lstnr->tcp_layer->context)->socket_manager->tcp_ipv4_conn_htable;
	if (!add_to_tcp_conn_hashtable(htable, conn)) {
		tcp_transition_to_state(conn, CLOSED);
		release_tcp_conn(conn); // last reference: destroys the connection
		return TCP_CONN_HTABLE_ADD_FAILED;
	}
	atomic_fetch_add(&lstnr->half_open_count, 1);
	tcp_transition_to_state(conn, SYN_RECEIVED);
	tcp_syn_to_snd_buff(conn);
	release_tcp_conn(conn);
	return CONN_CREATED_SYN_ACK_TO_SND_BUFFER;
}

// if local_addr is supplied, accept only connections for this address
// else wildcard listener
// (CURRENT API ONLY SUPPORTS WILDCARD CREATION)
struct tcp_ipv4_listener *create_tcp_listener(uint16_t port,
					      ipv4_address_t local_addr,
					      struct stack *stack)
{
	struct tcp_ipv4_listener *listener = malloc(sizeof(struct tcp_ipv4_listener));
	if (listener == NULL)
		return NULL;

	listener->ready_q = create_q(
	    q_release_tcp_conn, q_retain_tcp_conn, TCP_LSTNR_BACKLOG_DEFAULT);
	if (!listener->ready_q) {
		destroy_tcp_listener(listener);
		return NULL;
	}

	listener->ref_count = 0;
	listener->half_open_count = 0;
	listener->half_open_limit = TCP_LSTNR_HALF_OPENS_LIMIT;
	listener->local_port = port;
	if (!local_addr) {
		listener->wildcard = true;
		ipv4_address_t zero = {0};
		memcpy(listener->local_addr, zero, IPV4_ADDR_LEN);
	} else {
		listener->wildcard = false;
		memcpy(listener->local_addr, local_addr, IPV4_ADDR_LEN);
	}
	listener->tcp_layer = stack->tcp_layer;
	return listener;
}

void retain_tcp_listener(struct tcp_ipv4_listener *listener)
{
	atomic_fetch_add(&listener->ref_count, 1);
}

void release_tcp_listener(struct tcp_ipv4_listener *listener)
{
	if (atomic_fetch_sub(&listener->ref_count, 1) == 1)
		destroy_tcp_listener(listener);
}

void destroy_tcp_listener(struct tcp_ipv4_listener *listener)
{
	destroy_q(listener->ready_q);
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
	// mark q closed
	struct queue_node *node = close_q(listener->ready_q);
	// abort and release all connections from the q
	while (node) {
		struct queue_node *nxt = node->nxt;
		node->nxt = Q_NODE_UNLINKED;

		struct tcp_ipv4_conn *c = CONTAINER_OF(node, struct tcp_ipv4_conn, q_node);
		abort_tcp_conn(c);
		release_tcp_conn(c);
		node = nxt;
	}
}

struct tcp_ipv4_conn *tcp_lstnr_accept_conn(void *s)
{
	struct tcp_ipv4_listener *listener = (struct tcp_ipv4_listener *)s;
	struct queue_node *n = pop_q_blocking(listener->ready_q);
	if (!n)
		return NULL;

	return CONTAINER_OF(n, struct tcp_ipv4_conn, q_node);
}