#include "window_helpers.h"
#include "tcp_conn_socket.h"
#include <stdio.h>

// call when writing to receive buffer, and when app reads from buffer
// caller must hold lock
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
	struct byte_reassembly_rcv_buffer *rb = &conn->rcv_buffer;
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
		uint32_t stagnant_wnd;
		if (last_adv_bytes > current_free) {
			// decrease! scale down and clamp safely to 16 bits
			stagnant_wnd = current_free >> rb->rcv_wscale;
			if (stagnant_wnd > TCP_WND_FIELD_MAX) {
				stagnant_wnd = TCP_WND_FIELD_MAX;
			}
		} else {
			stagnant_wnd = rb->rcv_wnd;
		}
		return (uint16_t)stagnant_wnd;
	}

	// worthwhile increase
	uint32_t scaled_wnd = current_free >> rb->rcv_wscale;
	if (scaled_wnd > TCP_WND_FIELD_MAX) {
		scaled_wnd = TCP_WND_FIELD_MAX;
	}
	return (uint16_t)scaled_wnd;
}

uint8_t tcp_calc_wndw_scale(size_t buff_capacity)
{
	uint8_t scale = 0;
	uint32_t max_window = TCP_WND_FIELD_MAX;

	while (max_window < buff_capacity && scale < TCP_MAX_WND_SCALE) {
		max_window <<= 1;
		scale++;
	}

	return scale;
}

uint32_t usable_window(struct tcp_ipv4_conn *conn, uint32_t *peer_wnd_out)
{
	struct byte_snd_buffer *sb = &conn->snd_buffer;
	// ignore potential zero window for retransmissions
	if (sb->retransmit)
		return conn->snd_mss;

	uint32_t peer_wnd = (uint32_t)sb->snd_wndw << sb->snd_wscale;
	*peer_wnd_out = peer_wnd;
	uint32_t total_allowed = (peer_wnd < sb->cwnd) ? peer_wnd : sb->cwnd;
	printf("USABLE WINDOW: peer window: %u vs cong window: %u \n",
	       (uint32_t)sb->snd_wndw << sb->snd_wscale,
	       sb->cwnd);
	uint32_t sent_unacked = sb->snd_nxt - sb->snd_una;
	uint32_t sacked = sb->sacked_bytes;
	printf("SENT UNA: %d, SND NXT: %d, AMOUNT UNACKED:: %d \n",sb->snd_nxt, sb->snd_una, sb->snd_nxt - sb->snd_una);
	// pipe
	uint32_t effective_in_flight = (sent_unacked > sacked) ? (sent_unacked - sacked) : 0;
	printf("PIPE: %u \n\n", effective_in_flight);
	if (total_allowed > effective_in_flight)
		return total_allowed - effective_in_flight;

	return 0;
}