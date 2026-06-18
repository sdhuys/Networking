#pragma once
#include <stdint.h>
#include <stddef.h>

struct tcp_ipv4_conn;

#ifdef __cplusplus
extern "C" {
#endif

uint8_t tcp_calc_wndw_scale(size_t buff_capacity);
uint16_t calc_rcv_wnd_sws(struct tcp_ipv4_conn *conn);
uint32_t usable_window(struct tcp_ipv4_conn *conn, uint32_t *peer_wndw_out);

#ifdef __cplusplus
}
#endif
