#pragma once
#include "address_types.h"
#include "hash.h"
#include "socket_manager.h"
#include "tcp_conn_htable.h"
#include "tcp_conn_socket.h"
#include "tcp_listener_htable.h"
#include <stdlib.h>

extern const struct socket_ops tcp_listener_ops;

typedef enum { TCP_LIS_LISTEN, TCP_LIS_CLOSED } tcp_listener_state;

struct tcp_ipv4_listener {
	pthread_cond_t accept_cond;
	pthread_mutex_t lock; // also used to access half_open_count (defeats purpose of
			      // per bucket locks => switch to atomic cound in htable)

	ipv4_address local_addr;
	uint16_t local_port;
	tcp_listener_state state;

	struct tcp_ipv4_conn_htable *half_opens;
	size_t half_open_limit;
	size_t half_open_count;
	struct tcp_ipv4_conn_q *ready_q;

	uint32_t ref_count;
};

struct tcp_ipv4_conn_q_node {
	struct tcp_ipv4_conn *conn;
	struct tcp_ipv4_conn_q_node *next;
};

// listener's established connections backlog queues
// only accessed while listener is under lock
struct tcp_ipv4_conn_q {
	struct tcp_ipv4_conn_q_node *head;
	struct tcp_ipv4_conn_q_node *tail;
	size_t len;
};

struct tcp_ipv4_listener *create_tcp_listener(uint16_t port, struct stack *stack);
void destroy_tcp_listener(struct tcp_ipv4_listener *listener);
void retain_tcp_listener(struct tcp_ipv4_listener *listener);
void release_tcp_listener(struct tcp_ipv4_listener *listener);
void tcp_close_listener(struct stack *stack, void *s);
void tcp_lock_listener(void *s);
void tcp_unlock_listener(void *s);
void tcp_retain_listener(void *s);
void tcp_release_listener(void *s);
struct tcp_ipv4_conn_q *create_ready_q();
void destroy_ready_q(struct tcp_ipv4_conn_q *q);

pkt_result process_incoming_syn(struct tcp_ipv4_listener *listener,
				struct tcp_segment seg_in,
				struct pkt *p);
uint32_t generate_syn_cookie_iss(struct tcp_ipv4_listener *listener,
				 struct tcp_segment seg,
				 struct pkt *p);
pkt_result syn_cookie_check_ack(struct tcp_ipv4_listener *listener, struct tcp_segment seg);
pkt_result half_open_check_ack(struct tcp_segment seg,
			       struct tcp_ipv4_conn *half_open,
			       struct tcp_ipv4_listener *lstnr);
