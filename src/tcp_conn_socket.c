#include "tcp_conn_socket.h"
#include "tcp.h"

pkt_result process_tcp_segment(struct tcp_segment *seg, struct tcp_ipv4_conn *connection)
{
	uint32_t seq = ntohl(seg->header->seq_num);
	if (seg->header->flags & TCP_RST) {
		// NOTIFY APPLICATION
		return NOT_IMPLEMENTED_YET;
	}

	uint32_t rcv_next = connection->rcv_buffer->rcv_nxt;
	uint16_t rcv_wnd = connection->rcv_wnd;

	// safe version of "seq < rcv_next" if seq is right after overflowing
	if ((int32_t)(seq - rcv_next) < 0)
		return TCP_SEQ_DUPLICATE;

	// safe version of "seq > rcv_next + connection->rcv_wnd" if seq is right after overflowing
	if ((int32_t)(seq - (rcv_next + rcv_wnd)) > 0)
		return TCP_SEQ_OUT_OF_WNDW_RANGE_RST;

	return NOT_IMPLEMENTED_YET;
}

uint32_t generate_random_iss()
{
	uint32_t x;
	if (getrandom(&x, sizeof(x), 0) != sizeof(x))
		abort();
	return x;
}

struct tcp_ipv4_conn *create_tcp_connection(struct tcp_segment *seg, uint32_t iss)
{
	return NULL;
}

void destroy_tcp_conn(struct tcp_ipv4_conn *connection)
{
	// free stuff
}

// also sets the field
uint16_t calculate_rcv_wnd_sws(struct tcp_ipv4_conn *conn)
{
	size_t occupied = conn->rcv_buffer->contiguous_bytes + conn->rcv_buffer->ooo_bytes;
	if (occupied >= conn->rcv_buffer->capacity)
		return 0;

	size_t current_free = conn->rcv_buffer->capacity - occupied;

	// silly window syndrome avoidance, check if potential increase is > threshold worth
	// mentioning
	uint32_t last_adv_bytes = (uint32_t)conn->rcv_wnd << conn->rcv_wscale;

	size_t threshold = (conn->mss < (conn->rcv_buffer->capacity / 2))
			       ? conn->mss
			       : (conn->rcv_buffer->capacity / 2);

	// either no worthwhile increase OR decrease
	if (current_free < last_adv_bytes + threshold) {
		uint32_t stagnant_wnd = (last_adv_bytes > current_free)
					    ? (current_free >> conn->rcv_wscale)
					    : conn->rcv_wnd;
		return (uint16_t)stagnant_wnd;
	}

	// worthwhile increase
	uint32_t scaled_window = (uint32_t)(current_free >> conn->rcv_wscale);

	if (scaled_window > 0xFFFF)
		scaled_window = 0xFFFF;

	conn->rcv_wnd = (uint16_t)scaled_window;
	return (uint16_t)scaled_window;
}

uint32_t seg_len(struct tcp_segment *seg)
{
	uint32_t len = seg->payload_len;

	if (seg->header->flags & TCP_SYN)
		len++;
	if (seg->header->flags & TCP_FIN)
		len++;

	return len;
}
