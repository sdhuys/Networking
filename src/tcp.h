#pragma once
#include "buffer_pool.h"
#include "checksum.h"
#include "layer_router.h"
#include "socket_manager.h"
#include "syn_cookie.h"
#include "tcp_common_types.h"
#include "tcp_conn_htable.h"
#include "tcp_conn_socket.h"
#include "tcp_listener_htable.h"
#include "tcp_listener_socket.h"
#include "tcp_options.h"
#include <arpa/inet.h>

struct tcp_context {
	struct socket_manager *socket_manager;
	struct timer_min_heap *timers;
};

#ifdef __cplusplus
extern "C" {
#endif

pkt_result send_tcp_down(struct nw_layer *self, struct pkt *packet);
pkt_result receive_tcp_up(struct nw_layer *self, struct pkt *packet);
bool bogus_flags_any(uint16_t flags);
uint16_t calc_tcp_checksum(struct pkt *packet);
pkt_result tcp_fast_reply_rst(struct nw_layer *tcp,
			      struct tcp_ipv4_conn *conn,
			      struct pkt *packet,
			      struct tcp_segment *seg);
void init_reply_packet_from_incoming(struct pkt *pkt, const struct tcp_segment *seg);
pkt_result tcp_fast_reply_syn_cookie(struct nw_layer *tcp,
				     struct tcp_ipv4_listener *listener,
				     struct pkt *packet,
				     struct tcp_segment *seg);
#ifdef __cplusplus
}
#endif
