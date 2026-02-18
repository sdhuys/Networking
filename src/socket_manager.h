#pragma once
#include "socket_types.h"
#include "tcp_listener_htable.h"
#include "tcp_listener_socket.h"
#include "types.h"
#include "udp_hashtable.h"
#include "udp_socket.h"
#include <stdlib.h>

struct socket_handle {
	void *sock;
	const struct socket_ops *ops; // should contain all type-specific actions
};

struct socket_ops {
	bool (*is_snd_queued)(void *sock);
	void (*set_snd_queued)(void *sock, bool);

	void (*retain)(void *sock);
	void (*release)(void *sock);

	bool (*write_to_snd_buffer)(struct stack *stack, void *sock, struct send_request req);
	int (*read_rcv_buffer)(void *sock, size_t len, unsigned char *buff);
	int (*read_rcv_buffer_from)(
	    void *sock, size_t len, unsigned char *buff, ipv4_address addr_out, uint16_t *port_out);

	void (*unlock)(void *sock);
	void (*lock)(void *sock);

	struct pkt *(*next_snd_pkt)(void *);
	pkt_result (*send_pkt)(struct stack *, struct pkt *);

	void (*close)(struct stack *stack, void *sock);
};

struct socket_manager {
	struct tcp_ipv4_listener_htable *tcp_ipv4_listener_htable;
	struct tcp_ipv4_conn_htable *tcp_ipv4_conn_htable;
	struct tcp_ipv4_conn_htable *tcp_ipv4_conn_time_wait_htable;
	struct udp_ipv4_sckt_htable *udp_ipv4_sckt_htable;
	struct socket_h_q *send_down_sock_q; // app writes, stack reads
	struct sockfd_manager *sockfd_manager;
};

struct socket_h_q {
	struct socket_h_q_node *head;
	struct socket_h_q_node *tail;
	pthread_mutex_t lock;
	pthread_cond_t cond;
	size_t len;
};

struct socket_h_q_node {
	struct socket_handle socket;
	struct socket_h_q_node *next;
};

void notify_socket_readable_snd(struct socket_manager *mgr,
				void *sock,
				const struct socket_ops *ops);
struct socket_handle dequeue_sock_snd_down_q(struct socket_manager *mgr);
void release_socket_from_queue(struct socket_handle sock);
struct socket_h_q_node *dequeue_q_node(struct socket_h_q *q);
void enqueue_socket(struct socket_h_q *q, struct socket_handle sock);
int create_socket_handle(struct stack *stack,
			 socket_type type,
			 uint16_t local_port,
			 struct socket_handle *out);
