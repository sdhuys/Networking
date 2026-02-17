#pragma once
#include "types.h"
#include <stdlib.h>

#define TCP_LSTNR_HALF_OPENS_BCKT_COUNT 1024
#define TCP_LSTNR_HALF_OPENS_LIMIT 256

extern const struct socket_ops_t tcp_listener_ops;

struct tcp_ipv4_listener_t *create_tcp_listener(uint16_t port, struct stack_t *stack);
void destroy_tcp_listener(struct tcp_ipv4_listener_t *listener);
void retain_tcp_listener(struct tcp_ipv4_listener_t *listener);
void release_tcp_listener(struct tcp_ipv4_listener_t *listener);
void tcp_close_listener(void *s);
void tcp_lock_listner(void *s);
void tcp_unlock_listner(void *s);
void tcp_retain_listener(void *s);
void tcp_release_listener(void *s);
struct tcp_ipv4_conn_q_t *create_ready_q();
void destroy_ready_q(struct tcp_ipv4_conn_q_t *q);

typedef enum { TCP_LIS_LISTEN, TCP_LIS_CLOSED } tcp_listener_state_t;

struct tcp_ipv4_listener_t {
	pthread_cond_t accept_cond;
	pthread_mutex_t lock;

	ipv4_address local_addr;
	uint16_t local_port;
	tcp_listener_state_t state;

	struct tcp_ipv4_conn_htable_t *half_opens;
	uint16_t half_open_limit;
	struct tcp_ipv4_conn_q_t *ready_q;

	struct socket_manager_t *mgr;
	uint32_t ref_count;
};

struct tcp_ipv4_conn_q_node_t {
	struct tcp_ipv4_conn_t *conn;
	struct tcp_ipv4_conn_q_node_t *next;
};

// listener's established connections backlog queues
// only accessed while listener is under lock
struct tcp_ipv4_conn_q_t {
	struct tcp_ipv4_conn_q_node_t *head;
	struct tcp_ipv4_conn_q_node_t *tail;
	size_t len;
};
