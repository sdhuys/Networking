#pragma once
#include "address_types.h"
#include "hash.h"
#include "queue.h"
#include "socket_manager.h"
#include "tcp.h"
#include "tcp_conn_htable.h"
#include "tcp_conn_socket.h"
#include "tcp_listener_htable.h"
#include <stdlib.h>

extern const struct socket_ops tcp_listener_ops;

typedef enum { TCP_LIS_LISTEN, TCP_LIS_CLOSED } tcp_listener_state;

struct tcp_ipv4_listener {
	pthread_cond_t accept_cond;
	pthread_mutex_t lock;

	ipv4_address_t local_addr;
	uint16_t local_port;
	tcp_listener_state state;

	size_t half_open_limit;
	size_t half_open_count;
	struct queue *ready_q;

	uint32_t ref_count;
	struct nw_layer *tcp_layer;
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

pkt_result tcp_server_open_new_connection(struct tcp_ipv4_listener *lis,
					  struct pkt *pkt,
					  struct tcp_segment *seg);
struct tcp_ipv4_conn *tcp_lstnr_accept_conn(void *s);
