#pragma once
#include "address_types.h"
#include "pkt_result.h"
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define TCP_LSTNR_BACKLOG_DEFAULT 128

extern const struct socket_ops tcp_listener_ops;

struct stack;
struct nw_layer;
struct pkt;
struct queue;
struct tcp_segment;

struct tcp_ipv4_listener {
	ipv4_address_t local_addr;
	bool wildcard; // accept any local addr
	uint16_t local_port;

	size_t half_open_limit;
	atomic_uint half_open_count;
	struct queue *ready_q;

	atomic_uint ref_count;
	struct nw_layer *tcp_layer;
};

#ifdef __cplusplus
extern "C" {
#endif

struct tcp_ipv4_listener *create_tcp_listener(uint16_t port,
					      ipv4_address_t local_addr,
					      struct stack *stack);
void destroy_tcp_listener(struct tcp_ipv4_listener *listener);
void retain_tcp_listener(struct tcp_ipv4_listener *listener);
void release_tcp_listener(struct tcp_ipv4_listener *listener);
void tcp_close_listener(struct stack *stack, void *s);
void tcp_retain_listener(void *s);
void tcp_release_listener(void *s);

pkt_result tcp_server_open_new_connection(struct tcp_ipv4_listener *lis,
					  struct pkt *pkt,
					  struct tcp_segment *seg);
struct tcp_ipv4_conn *tcp_lstnr_accept_conn(void *s);

#ifdef __cplusplus
}
#endif
