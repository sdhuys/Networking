#include "window_helpers.h"
#include "tcp_conn_socket.h"

uint16_t calc_rcv_wnd_sws(struct tcp_ipv4_conn *conn)
{
	/* only consider the contiguous bytes as occupied, not ooo bytes. to avoid order of segments
	arriving impacting acceptance decision.

	Consider the following scenario:

	rcv_nxt = 1
	rcv_wndw = 100
	incoming segment: [50, 80) : 30 ooo bytes stored
	--------------------------
	rcv_next = 1
	rcv_wndw = 70
	incoming segment: [80, 100) : OUTSIDE OF RECEIVE WINDOW, NOT STORED


	Alternative arrival order:

	rcv_next = 1
	rcv_wndw = 100
	incoming segment: [80, 100) : 20 ooo bytes stored
	-------------------------
	rcv_next = 1
	rcv_wndw = 80
	incoming segment: [50, 80) : 30 ooo bytes stored
	*/
	size_t occupied = conn->rcv_buffer->contiguous_bytes;
	if (occupied >= conn->rcv_buffer->capacity)
		return 0;

	size_t current_free = conn->rcv_buffer->capacity - occupied;

	// silly window syndrome avoidance, check if potential increase is > threshold worth
	// mentioning
	uint32_t last_adv_bytes = (uint32_t)conn->rcv_buffer->rcv_wnd << conn->rcv_wscale;

	// if buffer is tiny, don't wait for mss
	size_t threshold = (conn->rcv_mss < (conn->rcv_buffer->capacity / 2))
			       ? conn->rcv_mss
			       : (conn->rcv_buffer->capacity / 2);

	// either no worthwhile increase OR decrease
	if (current_free < last_adv_bytes + threshold) {
		uint32_t stagnant_wnd = (last_adv_bytes > current_free)
					    ? (current_free >> conn->rcv_wscale)
					    : conn->rcv_buffer->rcv_wnd;
		return (uint16_t)stagnant_wnd;
	}

	// worthwhile increase
	uint32_t scaled_window = (uint32_t)(current_free >> conn->rcv_wscale);
	return (uint16_t)scaled_window;
}

uint8_t tcp_calc_wndw_scale()
{
	uint8_t scale = 0;
	uint32_t max_window = TCP_WND_FIELD_MAX;

	while (max_window < TCP_MAX_BUFFER_SIZE && scale < TCP_MAX_WND_SCALE) {
		max_window <<= 1;
		scale++;
	}

	return scale;
}

uint32_t usable_window(struct tcp_ipv4_conn *conn)
{
	struct byte_snd_buffer *buff = conn->snd_buffer;

	uint32_t total_allowed =
	    (conn->rcv_buffer->rcv_wnd < conn->cwnd) ? conn->rcv_buffer->rcv_wnd : conn->cwnd;

	uint32_t sent_unacked = buff->snd_nxt - buff->snd_una;
	uint32_t sacked = buff->sacked_bytes;

	uint32_t effective_in_flight;
	// if in recovery mode, everything still in flight considered lost
	// can result in great number of unnecessary retransmissions if SACK is disabled
	// with SACK enabled, damage should be limited (RX thread updates SACK blocks=> limits what
	// TX sends)
	if (conn->snd_buffer->rcov_mode)
		effective_in_flight = 0;
	else
		effective_in_flight = (sent_unacked > sacked) ? (sent_unacked - sacked) : 0;

	if (total_allowed > effective_in_flight)
		return total_allowed - effective_in_flight;

	return 0;
}