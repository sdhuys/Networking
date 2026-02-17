#pragma once
#include "socket_types.h"
#include "tcp_listener_htable.h"
#include "tcp_listener_socket.h"
#include "types.h"
#include "udp_hashtable.h"
#include "udp_socket.h"
#include <stdlib.h>

struct socket_handle_t {
	void *sock;
	const struct socket_ops_t *ops; // should contain all type-specific actions
};

struct socket_ops_t {
	bool (*is_snd_queued)(void *sock);
	void (*set_snd_queued)(void *sock, bool);

	void (*retain)(void *sock);
	void (*release)(void *sock);

	bool (*write_to_snd_buffer)(void *sock, struct send_request_t req);
	int (*read_rcv_buffer)(void *sock, size_t len, unsigned char *buff);
	int (*read_rcv_buffer_from)(
	    void *sock, size_t len, unsigned char *buff, ipv4_address addr_out, uint16_t *port_out);

	void (*unlock)(void *sock);
	void (*lock)(void *sock);

	struct pkt_t *(*next_snd_pkt)(void *);
	pkt_result (*send_pkt)(struct stack_t *, struct pkt_t *);

	void (*close)(void *sock);
};

struct socket_manager_t {
	struct tcp_ipv4_listener_htable_t *tcp_ipv4_listener_htable;
	struct tcp_ipv4_conn_htable_t *tcp_ipv4_conn_htable;
	struct tcp_ipv4_conn_htable_t *tcp_ipv4_conn_time_wait_htable;
	struct udp_ipv4_sckt_htable_t *udp_ipv4_sckt_htable;
	struct socket_h_q_t *send_down_sock_q; // app writes, stack reads
	struct sockfd_manager_t *sockfd_manager;
};

struct socket_h_q_t {
	struct socket_h_q_node_t *head;
	struct socket_h_q_node_t *tail;
	pthread_mutex_t lock;
	pthread_cond_t cond;
	size_t len;
};

struct socket_h_q_node_t {
	struct socket_handle_t socket;
	struct socket_h_q_node_t *next;
};

void notify_socket_readable_snd(struct socket_manager_t *mgr,
				void *sock,
				const struct socket_ops_t *ops);
struct socket_handle_t dequeue_sock_snd_down_q(struct socket_manager_t *mgr);
void release_socket_from_queue(struct socket_handle_t sock);
struct socket_h_q_node_t *dequeue_q_node(struct socket_h_q_t *q);
void enqueue_socket(struct socket_h_q_t *q, struct socket_handle_t sock);
int create_socket_handle(struct stack_t *stack,
			 socket_type_t type,
			 uint16_t local_port,
			 struct socket_handle_t *out);
