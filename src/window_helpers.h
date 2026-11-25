#pragma once
#include "tcp_segment.h"
#include "tcp_common_types.h"
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

static inline uint32_t tcp_seg_wnd_bytes(const struct tcp_segment *seg, uint8_t snd_wscale)
{
	uint32_t wnd = ntohs(seg->header->window);
	return (seg->header->flags & TCP_SYN) ? wnd : wnd << snd_wscale;
}

#ifdef __cplusplus
}
#endif
