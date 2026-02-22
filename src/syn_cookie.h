#pragma once
#include "tcp_common_types.h"
#include "tcp_listener_socket.h"
#include "types.h"
#include <stdint.h>

uint32_t generate_syn_cookie_iss(struct tcp_ipv4_listener *listener,
				 struct tcp_segment *seg,
				 struct pkt *p);
pkt_result syn_cookie_check_ack(struct tcp_ipv4_listener *listener,
				struct tcp_segment *seg,
				struct pkt *p);