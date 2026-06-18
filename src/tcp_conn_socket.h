#pragma once
#include "address_types.h"
#include "byte_ring_buffers.h"
#include "pkt_result.h"
#include "queue.h"
#include "tcp_common_types.h"
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

extern const struct socket_ops tcp_conn_ops;

#define TCP_INIT_RTO_MS 1000
#define TCP_DEL_ACK_MS 200
#define TCP_INIT_CWND_MSS_MULT 10
#define TCP_WND_FIELD_MAX 0xFFFF
#define TCP_MAX_WND_SCALE 14		// per RFC 7323
#define TCP_DEFAULT_BUFFER_SIZE 0x80000 // 512KB
#define TCP_MAX_BUFFER_SIZE 0x80000	// useful when we implement dynamic buffer growth
#define TCP_TIMEWAIT_MS 60000		// 1 min time_wait
#define TCP_MAX_RTO_MS 60000
#define TCP_MAX_ZWP_MS 60000

typedef enum {
	CLOSED,
	SYN_SENT,     // Sent SYN, waiting for SYN+ACK
	SYN_RECEIVED, // Received SYN, sent SYN+ACK
	ESTABLISHED,  // Connection established
	CLOSE_WAIT,   // Received FIN from remote, waiting for application close
	FIN_WAIT_1,   // Application closed, sent FIN, waiting for ACK
	FIN_WAIT_2,   // Received ACK of FIN, waiting for remote FIN
	CLOSING,      // Simultaneous close, sent FIN, waiting for ACK of FIN
	LAST_ACK,     // Waiting for ACK of our FIN after close
	TIME_WAIT     // Waiting for 2*MSL (maximum segment lifetime) before releasing
} tcp_connection_state;

struct timer;
struct pkt;
struct tcp_segment;
struct stack;
struct send_request;

struct tcp_ipv4_conn {
	pthread_mutex_t
	    lock; // global lock for state checks/transitions (e.g., ESTABLISHED -> FIN_WAIT)
	pthread_cond_t estblshd_cond; // broadcast for connect/accept

	struct byte_reassembly_rcv_buffer rcv_buffer;
	struct byte_snd_buffer snd_buffer;
	struct timer *rto_timer;
	uint32_t rto_interval; // Current Retransmission Timeout value

	ipv4_address_t local_addr;
	ipv4_address_t extern_addr;
	uint16_t local_port;
	uint16_t extern_port;

	uint32_t ref_count;
	tcp_connection_state state;

	uint32_t iss; // initial Send Sequence
	uint32_t irs; // initial Receive Sequence

	uint32_t rcv_mss; // local mss
	uint32_t snd_mss; // peer's advertised mss (adjusted to effective MSS by substracting TS option len if enabled)

	// features & options
	uint32_t ts_recent;   // the last TSval received from peer (to echo back in TSecr)
	uint32_t ts_last_ack; // the last TSecr we received (to validate ACKs)
	// RTT Estimation (RFC 6298)
	uint32_t srtt;	 // Smoothed Round-Trip Time (in microseconds or ticks)
	uint32_t rttvar; // RTT Variation (mean deviation)

	bool ece_enabled; // set during handshake

	bool wscale_enabled;
	uint8_t dup_ack_cnt;
	bool sack_enabled;
	bool ts_enabled;

	// ACK controls
	bool ack_pending; // signifies timer is running
	struct timer *del_ack_timer;
	int8_t in_order_full_seg_count;

	// route
	struct route *route;

	// refs
	struct nw_layer *tcp_layer;
	struct tcp_ipv4_listener *lstnr;

	// TX queue flag
	bool queued_for_snd;

	// Zero window probe (instead of zero we use < MSS window)
	struct timer *zwp_timer; // start timer as soon as peer advertises window < mss
	bool is_wndw_probing;
	uint32_t zwp_interval;
	struct timer *time_wait_timer;

	// doesn't include TIME_WAIT timer!!
	bool data_timers_cancelled;

	// Intrusive data structures
	struct queue_node q_node;
};

#ifdef __cplusplus
extern "C" {
#endif

struct tcp_ipv4_conn *create_init_tcp_connection(struct tcp_conn_id *id, struct nw_layer *tcp);
void server_init_tcp_connection(struct tcp_ipv4_conn *conn, struct tcp_segment *seg);
void client_init_tcp_connection(struct tcp_ipv4_conn *conn);
void delayed_ack_callback(void *c);
void zwp_callback(void *c);
void rto_callback(void *c);
void time_wait_callback(void *c);
void fast_recovery(struct tcp_ipv4_conn *conn);
void stop_wndw_probing(struct tcp_ipv4_conn *conn);
void start_wndw_probing_timer(struct tcp_ipv4_conn *conn);

pkt_result tcp_fast_reply_pure_ack(struct pkt *p, struct tcp_ipv4_conn *conn);
void destroy_tcp_conn(struct tcp_ipv4_conn *conn);
uint32_t generate_random_iss();
pkt_result process_tcp_segment(struct pkt *p,
			       struct tcp_segment *seg,
			       struct tcp_ipv4_conn *connection);
void tcp_syn_to_snd_buff(struct tcp_ipv4_conn *conn);

void write_pkt_tcp_general_metadata(struct tcp_ipv4_conn *conn, struct pkt *p);
void tcp_init_packet_addresses(struct pkt *pkt, struct tcp_ipv4_conn *conn);

void tcp_transition_to_state(struct tcp_ipv4_conn *conn, tcp_connection_state state);

void retain_tcp_conn(struct tcp_ipv4_conn *conn);
void release_tcp_conn(struct tcp_ipv4_conn *conn);
void q_retain_tcp_conn(struct queue_node *n);
void q_release_tcp_conn(struct queue_node *n);

void tcp_retain_conn(void *s);
void tcp_release_conn(void *s);
void tcp_lock_conn(void *s);
void tcp_unlock_conn(void *s);
struct pkt *tcp_try_get_pkt(void *s);
pkt_result tcp_send_packet(struct stack *stack, struct pkt *p);
bool tcp_is_snd_queued(void *s);
void tcp_set_snd_queued(void *s, bool v);
void tcp_end_snd(struct stack *stack, void *sock);
void tcp_close_conn(struct stack *stack, void *sock);

static inline bool tcp_conn_alive(struct tcp_ipv4_conn *conn)
{
	return conn->state != CLOSED;
}

ssize_t tcp_write_to_snd_buff(struct stack *stack, void *sock, struct send_request *req);
ssize_t tcp_read_from_rcv_buff(void *sock, size_t len, unsigned char *buff);

#ifdef __cplusplus
}
#endif
