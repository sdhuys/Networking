#pragma once
#include "tcp_common_types.h"
#include "tcp_segment.h"
#include "time_now.h"
#include "types.h"
#include <arpa/inet.h>
#include <stdint.h>

struct tcp_ipv4_listener;
struct tcp_segment;

uint32_t generate_syn_cookie_iss(struct tcp_ipv4_listener *listener,
				 struct tcp_segment *seg,
				 struct pkt *p);
pkt_result syn_cookie_check_ack(struct tcp_ipv4_listener *listener,
				struct tcp_segment *seg,
				struct pkt *p);