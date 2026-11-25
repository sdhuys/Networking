#pragma once
// C interface between the gtest tests (C++) and the stack (C).
// The tests never include stack headers: several use <stdatomic.h> types that C++
// cannot compile. Everything they need goes through these functions.

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct th_stack th_stack;

// Called for every frame the stack sends (after Ethernet, before the wire).
// The frame bytes are only valid during the call.
typedef void (*th_tx_fn)(void *user, const uint8_t *frame, size_t len);

// TCP states, same order as tcp_connection_state in tcp_conn_socket.h
enum th_tcp_state {
	TH_CLOSED,
	TH_SYN_SENT,
	TH_SYN_RECEIVED,
	TH_ESTABLISHED,
	TH_CLOSE_WAIT,
	TH_FIN_WAIT_1,
	TH_FIN_WAIT_2,
	TH_CLOSING,
	TH_LAST_ACK,
	TH_TIME_WAIT,
};

struct th_conn_info {
	int state; // enum th_tcp_state
	bool in_time_wait_table;
	bool aborted;
	uint32_t iss, irs;
	uint32_t snd_una, snd_nxt, snd_wnd; // snd_wnd: peer's window in bytes (scale applied)
	uint32_t rcv_nxt, rcv_wnd;
	uint32_t snd_mss, rcv_mss;
	uint32_t cwnd, ssthresh;
	uint32_t rto_ms;
	bool sack_enabled, ts_enabled, wscale_enabled;
	bool retransmit, zero_window_probing;
	size_t snd_used_bytes, rcv_contiguous_bytes;
};

// ---- process-wide ----
void th_global_init(void);    // hash keys + packet pool; safe to call repeatedly
int th_pool_free_count(void); // packets currently free in the pool (single-threaded use only)

// ---- stacks ----
// Creates a stack with the given address on a /24 (e.g. "10.0.0.2") and MAC.
// Frames the stack sends go to tx_fn; nothing reaches a real device.
th_stack *th_stack_create(const char *ip, const uint8_t mac[6], th_tx_fn tx_fn, void *tx_user);
// Same, plus a default route via `gateway` (an address on the same /24), like main.c's
// default route via tap0.
th_stack *th_stack_create_gw(
    const char *ip, const uint8_t mac[6], const char *gateway, th_tx_fn tx_fn, void *tx_user);
void th_stack_add_arp(th_stack *s, const char *ip, const uint8_t mac[6]); // static neighbour
const uint8_t *th_stack_mac(th_stack *s);
struct stack *th_stack_raw(th_stack *s);

// Deliver a frame synchronously on the calling thread, as the RX thread would.
// Returns the stack's pkt_result value.
int th_inject(th_stack *s, const uint8_t *frame, size_t len);
// Queue a frame on the stack's ingress queue (for stacks running their RX thread).
// Returns false if the packet pool or the ingress queue is full (= frame lost).
bool th_enqueue_ingress(th_stack *s, const uint8_t *frame, size_t len);

// ---- driving a stack by hand (unit tests: no threads) ----
size_t th_pump_tx(
    th_stack *s); // runs the TX worker until its queue is empty; returns segments built
void th_run_timers(th_stack *s); // runs every timer that has expired at the current (fake) time
// processes what is waiting on the ingress queue (what loopback sent), without blocking;
// returns the number of frames processed
size_t th_drain_ingress(th_stack *s);

// ---- running a stack on its own threads (system tests) ----
void th_start_threads(th_stack *s); // RX (ingress queue), TX worker, timer thread

// ---- socket API (thin wrappers around api.h) ----
int th_listen(th_stack *s, uint16_t port);
int th_accept(th_stack *s, int listen_fd);
int th_connect(th_stack *s, uint16_t local_port, const char *peer_ip, uint16_t peer_port);
long th_send(th_stack *s, int fd, const void *data, size_t len); // loops until all written or error
long th_send_once(th_stack *s, int fd, const void *data, size_t len);
long th_recv(th_stack *s, int fd, void *buf, size_t len);
int th_end_send(th_stack *s, int fd);

// UDP: open a socket bound to `port`, send a datagram, receive one (with its source)
int th_udp_open(th_stack *s, uint16_t port);
long th_udp_sendto(
    th_stack *s, int fd, const void *data, size_t len, const char *dst_ip, uint16_t dst_port);
long th_udp_recvfrom(
    th_stack *s, int fd, void *buf, size_t len, uint8_t src_ip[4], uint16_t *src_port);
int th_close(th_stack *s, int fd);

// ---- inspection ----
// Looks the connection up in the main and TIME_WAIT tables. Returns false if it's in neither.
bool th_conn_lookup(th_stack *s,
		    uint16_t local_port,
		    const char *peer_ip,
		    uint16_t peer_port,
		    struct th_conn_info *out);

// ---- packets and packet ring buffers (opaque: struct pkt can't be used from C++) ----
void *th_pkt_alloc(void); // NULL if the pool is empty
unsigned th_pkt_refcount(void *p);
void th_pkt_retain(void *p);
void th_pkt_release(void *p);
void *th_ring_create(size_t capacity); // NULL unless capacity is a power of two
bool th_ring_write(void *ring, void *p);
void *th_ring_read(void *ring); // NULL if empty
void th_ring_destroy(void *ring);

#ifdef __cplusplus
}
#endif
