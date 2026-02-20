#pragma once
#include "buffer_pool.h"
#include "checksum.h"
#include "layer_router.h"
#include "socket_manager.h"
#include "tcp_conn_htable.h"
#include "tcp_conn_socket.h"
#include "tcp_listener_htable.h"
#include "tcp_listener_socket.h"
#include "types.h"
#include <arpa/inet.h>

#define TCP_FIN 0x01 // 0000 0001
#define TCP_SYN 0x02 // 0000 0010
#define TCP_RST 0x04 // 0000 0100
#define TCP_PSH 0x08 // 0000 1000
#define TCP_ACK 0x10 // 0001 0000
#define TCP_URG 0x20 // 0010 0000
#define TCP_ECE 0x40 // 0100 0000
#define TCP_CWR 0x80 // 1000 0000

#define TCP_MSS_DEFAULT_FALLBACK 536

#ifdef __cplusplus
extern "C" {
#endif

pkt_result send_tcp_down(struct nw_layer *self, struct pkt *packet);
pkt_result receive_tcp_up(struct nw_layer *self, struct pkt *packet);
bool bogus_flags_any(uint16_t flags);
uint16_t calc_tcp_checksum(struct pkt *packet);
pkt_result tcp_reply_rst(struct nw_layer *tcp,
			 struct tcp_ipv4_conn *conn,
			 struct pkt *packet,
			 struct tcp_header_no_options *header);

#ifdef __cplusplus
}
#endif
