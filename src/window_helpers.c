#include "window_helpers.h"
#include "tcp_conn_socket.h"

// call when writing to receive buffer, and when app reads from buffer
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
	struct byte_reassembly_rcv_buffer *rb = conn->rcv_buffer;
	lock_rcv_buff(rb);
	size_t occupied = rb->contiguous_bytes;
	if (occupied >= rb->capacity)
		return 0;

	size_t current_free = rb->capacity - occupied;

	// silly window syndrome avoidance, check if potential increase is > threshold worth
	// mentioning
	uint32_t last_adv_bytes = (uint32_t)rb->rcv_wnd << rb->rcv_wscale;

	// if buffer is tiny, don't wait for mss
	size_t threshold =
	    (conn->rcv_mss < (rb->capacity / 2)) ? conn->rcv_mss : (rb->capacity / 2);

	// either no worthwhile increase OR decrease
	if (current_free < last_adv_bytes + threshold) {
		uint32_t stagnant_wnd = (last_adv_bytes > current_free)
					    ? (current_free >> rb->rcv_wscale)
					    : rb->rcv_wnd;
		unlock_rcv_buff(rb);
		return (uint16_t)stagnant_wnd;
	}

	// worthwhile increase
	uint16_t scaled_window = (current_free > TCP_WND_FIELD_MAX && !conn->wscale_enabled)
				     ? TCP_WND_FIELD_MAX
				     : (uint16_t)(current_free >> rb->rcv_wscale);
	unlock_rcv_buff(rb);
	return scaled_window;
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
	struct byte_snd_buffer *sb = conn->snd_buffer;

	uint32_t total_allowed = ((uint32_t)(sb->snd_wndw << sb->snd_wscale) < sb->cwnd)
				     ? (uint32_t)(sb->snd_wndw << sb->snd_wscale)
				     : sb->cwnd;

	uint32_t sent_unacked = sb->snd_nxt - sb->snd_una;
	uint32_t sacked = sb->sacked_bytes;

	uint32_t effective_in_flight;
	// if in recovery mode, everything still in flight considered lost
	// can result in great number of unnecessary retransmissions if SACK is disabled
	// with SACK enabled, damage should be limited (RX thread updates SACK blocks=> limits what
	// TX sends)
	if (sb->rcov_mode)
		effective_in_flight = 0;
	else
		effective_in_flight = (sent_unacked > sacked) ? (sent_unacked - sacked) : 0;

	if (total_allowed > effective_in_flight)
		return total_allowed - effective_in_flight;

	return 0;
}