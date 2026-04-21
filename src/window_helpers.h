#pragma once
#include <stdint.h>

struct tcp_ipv4_conn;

#ifdef __cplusplus
extern "C" {
#endif

uint8_t tcp_calc_wndw_scale();
uint16_t calc_rcv_wnd_sws(struct tcp_ipv4_conn *conn);
uint32_t usable_window(struct tcp_ipv4_conn *conn);

#ifdef __cplusplus
}
#endif
