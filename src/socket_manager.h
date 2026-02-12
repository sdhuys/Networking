#pragma once
#include "types.h"
#include <stdlib.h>

void notify_socket_readable_rcv(struct socket_manager_t *mgr,
				void *sock,
				const struct socket_ops_t *ops);
void notify_socket_readable_snd(struct socket_manager_t *mgr,
				void *sock,
				const struct socket_ops_t *ops);
struct socket_handle_t dequeue_readable_socket(struct socket_manager_t *mgr);
struct socket_handle_t dequeue_writable_socket(struct socket_manager_t *mgr);
void release_socket_from_queue(struct socket_handle_t sock, bool rx);
struct socket_h_q_node_t *dequeue_socket(struct socket_h_q_t *q);
void enqueue_socket(struct socket_h_q_t *q, struct socket_handle_t sock);
