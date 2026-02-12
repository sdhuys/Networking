#include "tcp_listener_socket.h"

struct tcp_ipv4_listener_t *create_tcp_listener(uint16_t port, struct stack_t *stack)
{
	struct tcp_ipv4_listener_t *listener = malloc(sizeof(struct tcp_ipv4_listener_t));
	if (listener == NULL)
		return NULL;

	listener->half_open_q = malloc(sizeof(struct tcp_ipv4_conn_q_t));
	listener->ready_q = malloc(sizeof(struct tcp_ipv4_conn_q_t));
	if (!listener->half_open_q || !listener->ready_q) {
		free(listener);
		return NULL;
	}
	listener->local_port = port;
	memcpy(listener->local_addr, stack->local_address, IPV4_ADDR_LEN);
	listener->state = TCP_LISTEN;
	pthread_mutex_init(&listener->lock, NULL);
	return listener;
}