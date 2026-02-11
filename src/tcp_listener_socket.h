#pragma once
#include "types.h"

typedef enum { LISTENING, CLOSED } tcp_listener_state_t;

struct tcp_ipv4_listener_t
{
	ipv4_address local_addr;
	uint16_t local_port;
	tcp_listener_state_t state;
	struct tcp_ipv4_socket_q_t half_open_q;
	struct tcp_ipv4_socket_q_t ready_q;
	pthread_mutex_t lock;
};
