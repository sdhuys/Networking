#pragma once
#include "tcp_options.h"
#include "tcp_common_types.h"
#include "tcp_conn_socket.h"
#include "tcp_segment.h"
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>

struct tcp_ipv4_conn;

#ifdef __cplusplus
extern "C" {
#endif

uint8_t tcp_calc_wndw_scale(size_t buff_capacity);
uint16_t calc_rcv_wnd_sws(struct tcp_ipv4_conn *conn);
uint32_t usable_window(struct tcp_ipv4_conn *conn, uint32_t *peer_wndw_out);

static inline void tcp_negotiate_wscale(struct tcp_ipv4_conn *conn, const struct tcp_options *opt)
{
	if (conn->wscale_enabled && opt->wscale_present) {
		conn->snd_buffer.snd_wscale = opt->wscale; // already clamped to 14 by the parser
	} else {
		conn->wscale_enabled = false;
		conn->snd_buffer.snd_wscale = 0;
		conn->rcv_buffer.rcv_wscale = 0;
	}
}
static inline uint32_t tcp_seg_wnd_bytes(const struct tcp_segment *seg, uint8_t snd_wscale)
{
	uint32_t wnd = ntohs(seg->header->window);
	return (seg->header->flags & TCP_SYN) ? wnd : wnd << snd_wscale;
}

#ifdef __cplusplus
}
#endif
