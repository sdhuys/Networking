#pragma once
#include "pkt_result.h"
#include <stdint.h>

struct tcp_ipv4_listener;
struct tcp_segment;
struct pkt;

#ifdef __cplusplus
extern "C" {
#endif

uint32_t generate_syn_cookie_iss(struct tcp_ipv4_listener *listener,
				 struct tcp_segment *seg,
				 struct pkt *p);
pkt_result syn_cookie_check_ack(struct tcp_ipv4_listener *listener,
				struct tcp_segment *seg,
				struct pkt *p);

#ifdef __cplusplus
}
#endif
