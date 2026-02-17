#pragma once
#include "ring_buffer.h"
#include "timer.h"
#include "types.h"

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
} tcp_connection_state_t;

struct tcp_ipv4_conn_t {
	pthread_mutex_t lock;
	pthread_cond_t read_cond;

	struct tcp_ooo_ring_buffer_t ooo_buffer;
	struct tcp_rcv_ring_buffer_t rcv_buffer;
	struct tcp_snd_ring_buffer_t snd_buffer;
	struct timer_t rto_timer;

	ipv4_address local_addr;
	ipv4_address extern_addr;

	uint32_t ref_count;

	uint32_t iss, irs;
	uint32_t snd_una, snd_nxt, rcv_nxt;
	uint32_t snd_wnd, rcv_wnd;
	uint32_t cwnd, ssthresh;
	uint32_t mss;

	uint16_t local_port;
	uint16_t extern_port;
	tcp_connection_state_t state;

	uint8_t snd_wscale;
	uint8_t rcv_wscale;
	uint8_t dup_ack_cnt;
	bool sack_enabled;
	bool ts_enabled;
	bool ece_enabled;
};

void destroy_tcp_conn(struct tcp_ipv4_conn_t *connection);
