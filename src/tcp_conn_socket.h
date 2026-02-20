#pragma once
#include "byte_ring_buffers.h"
#include "pkt_ring_buffer.h"
#include "timer.h"
#include "types.h"
#include <arpa/inet.h>
#include <sys/random.h>

typedef enum {
	SYN_SENT,     // Sent SYN, waiting for SYN+ACK
	SYN_RECEIVED, // Received SYN, sent SYN+ACK
	ESTABLISHED,  // Connection established
	FIN_WAIT_1,   // Application closed, sent FIN, waiting for ACK
	FIN_WAIT_2,   // Received ACK of FIN, waiting for remote FIN
	CLOSE_WAIT,   // Received FIN from remote, waiting for application close
	CLOSING,      // Simultaneous close, sent FIN, waiting for ACK of FIN
	LAST_ACK,     // Waiting for ACK of our FIN after close
	TIME_WAIT     // Waiting for 2*MSL (maximum segment lifetime) before releasing
} tcp_connection_state;

struct tcp_ipv4_conn {
	pthread_mutex_t
	    lock; // global lock for state checks/transitions (e.g., ESTABLISHED -> FIN_WAIT)

	struct byte_reassembly_rcv_buffer *rcv_buffer;
	struct byte_snd_buffer *snd_buffer;
	struct timer rto_timer;

	ipv4_address local_addr;
	ipv4_address extern_addr;
	uint16_t local_port;
	uint16_t extern_port;

	uint32_t ref_count;
	tcp_connection_state state;

	uint32_t iss; // initial Send Sequence
	uint32_t irs; // initial Receive Sequence

	uint32_t cwnd;
	uint32_t ssthresh;
	uint32_t mss;
	uint32_t snd_wnd; // peer's advertised window (calculated with scale)
	uint32_t rcv_wnd; // last advertised rcv_window

	// features & options
	uint8_t snd_wscale;
	uint8_t rcv_wscale;
	uint8_t dup_ack_cnt;
	bool sack_enabled;
	bool ts_enabled;
	bool ece_enabled;
};
void destroy_tcp_conn(struct tcp_ipv4_conn *connection);
uint32_t tcp_generate_iss();
pkt_result process_tcp_segment(struct tcp_segment seg, struct tcp_ipv4_conn *connection);
uint16_t calculate_rcv_wnd_sws(struct tcp_ipv4_conn *conn);
