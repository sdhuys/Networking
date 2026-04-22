#pragma once
#include "address_types.h"
#include "pkt_result.h"
#include <stdbool.h>
#include <stdint.h>

struct socket_manager;
struct timer_manager;
struct routing_table;
struct nw_layer;
struct pkt;
struct tcp_ipv4_listener;
struct tcp_segment;

struct tcp_context {
	struct socket_manager *socket_manager;
	struct timer_manager *timer_mgr;
	ipv4_address_t stack_ipv4_addr;
	struct routing_table *routing_tbl;
};

#ifdef __cplusplus
extern "C" {
#endif

pkt_result send_tcp_down(struct nw_layer *self, struct pkt *packet);
pkt_result receive_tcp_up(struct nw_layer *self, struct pkt *packet);
bool bogus_flags_any(uint16_t flags);
uint16_t calc_tcp_checksum(struct pkt *packet);
pkt_result tcp_fast_reply_rst(struct nw_layer *tcp, struct pkt *packet, struct tcp_segment *seg);
void init_reply_packet_from_incoming(struct pkt *pkt, const struct tcp_segment *seg);
pkt_result tcp_fast_reply_syn_cookie(struct tcp_ipv4_listener *listener,
				     struct pkt *packet,
				     struct tcp_segment *seg);

#ifdef __cplusplus
}
#endif
