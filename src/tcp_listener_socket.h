#pragma once
#include "types.h"
#include <stdlib.h>

struct tcp_ipv4_listener_t *create_tcp_listener(uint16_t port, struct stack_t *stack);

typedef enum { TCP_LISTEN, TCP_CLOSED } tcp_listener_state_t;

// only lives in hashtable and app at same time. if closed/removed nothing should survive
struct tcp_ipv4_listener_t {
	ipv4_address local_addr;
	uint16_t local_port;
	tcp_listener_state_t state;
	struct tcp_ipv4_conn_q_t *half_open_q;
	struct tcp_ipv4_conn_q_t *ready_q;
	pthread_mutex_t lock;
};
