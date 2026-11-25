// Glue between the tests and the stack. Builds stacks without a TAP device, swaps the
// interface layer's send_down for a callback, and drives the TX worker and timers by hand.
// Uses only the stack's public headers and structs: nothing in src/ was changed for this.

#include "harness.h"

#include "api.h"
#include "arp.h"
#include "buffer_pool.h"
#include "container_of.h"
#include "ethernet.h"
#include "hash.h"
#include "ipv4.h"
#include "nw_interface.h"
#include "nw_layer.h"
#include "pkt.h"
#include "pkt_ring_buffer.h"
#include "queue.h"
#include "routing_table.h"
#include "socket_manager.h"
#include "stack.h"
#include "stack_constructor.h"
#include "stack_tx_worker.h"
#include "tap.h"
#include "tcp.h"
#include "tcp_common_types.h"
#include "tcp_conn_htable.h"
#include "tcp_conn_socket.h"
#include "timer.h"
#include "timer_worker.h"
#include "udp.h"

#include <arpa/inet.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TH_MAX_STACKS 4096

struct th_stack {
	struct stack *stack;
	struct nw_interface ifaces[2]; // [0] test0 (the "wire"), [1] loopback
	uint8_t mac[6];
	uint8_t ip[4];
	th_tx_fn tx_fn;
	void *tx_user;
};

// interface -> harness stack, so the transmit replacement finds its callback
static struct th_stack *registry[TH_MAX_STACKS];
static _Atomic size_t registry_count;

static pthread_once_t global_once = PTHREAD_ONCE_INIT;

static void global_init_once(void)
{
	hash_init();
	init_buffer_pool();
}

void th_global_init(void)
{
	pthread_once(&global_once, global_init_once);
}

int th_pool_free_count(void)
{
	static struct pkt *taken[PKT_BUFF_POOL_SIZE];
	int n = 0;
	while (n < PKT_BUFF_POOL_SIZE) {
		struct pkt *p = allocate_pkt();
		if (!p)
			break;
		taken[n++] = p;
	}
	for (int i = 0; i < n; i++)
		release_pkt(taken[i]);
	return n;
}

static struct th_stack *find_by_iface(const struct nw_interface *nif)
{
	size_t n = atomic_load(&registry_count);
	for (size_t i = 0; i < n; i++)
		if (&registry[i]->ifaces[0] == nif)
			return registry[i];
	return NULL;
}

// transmit function of the test0 interface (replaces tap_transmit): hands the frame to the test
static pkt_result th_transmit(struct interface_context *ctx,
			      struct nw_interface *nif,
			      struct pkt *p)
{
	(void)ctx;
	struct th_stack *s = find_by_iface(nif);
	if (!s)
		return WRITE_ERROR;
	if (s->tx_fn)
		s->tx_fn(s->tx_user, p->data + p->offset, p->len);
	return SENT;
}

static void parse_ip(const char *str, uint8_t out[4])
{
	struct in_addr a;
	if (inet_pton(AF_INET, str, &a) != 1) {
		fprintf(stderr, "harness: bad IP address '%s'\n", str);
		abort();
	}
	memcpy(out, &a.s_addr, 4);
}

th_stack *th_stack_create(const char *ip, const uint8_t mac[6], th_tx_fn tx_fn, void *tx_user)
{
	return th_stack_create_gw(ip, mac, NULL, tx_fn, tx_user);
}

th_stack *th_stack_create_gw(
    const char *ip, const uint8_t mac[6], const char *gateway, th_tx_fn tx_fn, void *tx_user)
{
	th_global_init();

	struct th_stack *s = calloc(1, sizeof(*s));
	parse_ip(ip, s->ip);
	memcpy(s->mac, mac, 6);
	s->tx_fn = tx_fn;
	s->tx_user = tx_user;

	// same two interfaces as main.c: the "wire" on a /24, and loopback.
	// construct_stack keeps a pointer to this array, so it lives in th_stack.
	const uint8_t mask24[4] = {255, 255, 255, 0};
	const uint8_t lo_ip[4] = {127, 0, 0, 1};
	const uint8_t lo_mask[4] = {255, 0, 0, 0};
	const uint8_t lo_mac[6] = {0};
	set_nw_if_struct(&s->ifaces[0], -1, "test0", mac, s->ip, mask24, 1500, th_transmit, 0);
	set_nw_if_struct(&s->ifaces[1],
			 -1,
			 "lo",
			 lo_mac,
			 lo_ip,
			 lo_mask,
			 1500,
			 loopback_transmit,
			 IF_NOARP | IF_LOOPBACK);

	// register before construct_stack: nothing is sent during construction, but keep the
	// lookup valid from the moment the interface exists
	size_t idx = atomic_fetch_add(&registry_count, 1);
	if (idx >= TH_MAX_STACKS) {
		fprintf(stderr, "harness: too many stacks\n");
		abort();
	}
	registry[idx] = s;

	// optional default route via a gateway on the test0 subnet, as main.c does via tap0
	struct static_route default_route = {.prefix = {0}, .mask = {0}};
	size_t static_count = 0;
	if (gateway) {
		parse_ip(gateway, default_route.gateway);
		static_count = 1;
	}

	struct stack *st = construct_stack(s->ifaces, 2, &default_route, static_count);
	if (!st) {
		fprintf(stderr, "harness: construct_stack failed\n");
		abort();
	}
	s->stack = st;
	return s;
}

void th_stack_add_arp(th_stack *s, const char *ip, const uint8_t mac[6])
{
	uint8_t addr[4];
	parse_ip(ip, addr);
	struct nw_layer *arp = s->stack->if_layer->ups[0]->ups[0];
	struct arp_table *table = ((struct arp_context *)arp->context)->arp_table;
	pthread_mutex_lock(&table->lock);
	struct arp_table_node *node = query_arp_table(table, addr);
	if (!node)
		node = insert_incomplete_for_ip(table, addr, 0);
	complete_arp_table_node(node, (unsigned char *)mac);
	pthread_mutex_unlock(&table->lock);
}

const uint8_t *th_stack_mac(th_stack *s)
{
	return s->mac;
}

struct stack *th_stack_raw(th_stack *s)
{
	return s->stack;
}

int th_inject(th_stack *s, const uint8_t *frame, size_t len)
{
	if (len > PKT_SIZE)
		return -1;
	struct pkt *p = allocate_pkt();
	if (!p)
		return -1;
	if (len)
		memcpy(p->data, frame, len);
	p->offset = 0;
	p->len = len;
	p->if_index = 0; // arrived on test0, as read_from_interface marks frames from tap0
	struct nw_layer *ifl = s->stack->if_layer;
	int r = ifl->rcv_up(ifl, p);
	release_pkt(p);
	return r;
}

bool th_enqueue_ingress(th_stack *s, const uint8_t *frame, size_t len)
{
	if (len > PKT_SIZE)
		return false;
	struct pkt *p = allocate_pkt();
	if (!p)
		return false;
	if (len)
		memcpy(p->data, frame, len);
	p->offset = 0;
	p->len = len;
	p->if_index = 0;
	struct interface_context *ic = (struct interface_context *)s->stack->if_layer->context;
	bool ok = push_q(ic->ingress_q, &p->q_node); // the queue takes its own reference
	release_pkt(p);
	return ok;
}

size_t th_pump_tx(th_stack *s)
{
	// same as the inner loop of stack_transmission_loop, without blocking
	struct stack *st = s->stack;
	size_t built = 0;
	for (;;) {
		struct socket_handle h = dequeue_sock_snd_down_q(st->sock_manager);
		if (!h.sock)
			break;
		struct pkt *p;
		while ((p = h.ops->try_get_pkt(h.sock)) != NULL) {
			h.ops->send_pkt(st, p);
			release_pkt(p);
			built++;
		}
		release_socket(h);
	}
	return built;
}

size_t th_drain_ingress(th_stack *s)
{
	// same as process_ingress_q_packets, without blocking: what loopback queued
	struct nw_layer *ifl = s->stack->if_layer;
	struct interface_context *ic = (struct interface_context *)ifl->context;
	size_t n = 0;
	struct queue_node *node;
	while ((node = pop_q(ic->ingress_q)) != NULL) {
		struct pkt *p = CONTAINER_OF(node, struct pkt, q_node);
		ifl->rcv_up(ifl, p);
		release_pkt(p);
		n++;
	}
	return n;
}

void th_run_timers(th_stack *s)
{
	execute_exp_timers(s->stack->timer_mgr);
}

static void *rx_thread(void *arg)
{
	struct th_stack *s = arg;
	process_ingress_q_packets(s->stack->if_layer);
	return NULL;
}

void th_start_threads(th_stack *s)
{
	pthread_t t;
	pthread_create(&t, NULL, rx_thread, s);
	pthread_detach(t);
	pthread_create(&t, NULL, stack_transmission_loop, s->stack);
	pthread_detach(t);
	pthread_create(&t, NULL, start_timers_loop, s->stack);
	pthread_detach(t);
}

int th_listen(th_stack *s, uint16_t port)
{
	return open_listener(s->stack, SOCK_TCP, port);
}

int th_accept(th_stack *s, int listen_fd)
{
	return accept_connection(s->stack, listen_fd);
}

int th_connect(th_stack *s, uint16_t local_port, const char *peer_ip, uint16_t peer_port)
{
	uint8_t addr[4];
	parse_ip(peer_ip, addr);
	return tcp_connect(s->stack, local_port, peer_port, addr);
}

long th_send_once(th_stack *s, int fd, const void *data, size_t len)
{
	struct send_request req = {.data = (unsigned char *)data, .len = len};
	return send_down(s->stack, fd, &req);
}

long th_send(th_stack *s, int fd, const void *data, size_t len)
{
	size_t done = 0;
	while (done < len) {
		long r = th_send_once(s, fd, (const uint8_t *)data + done, len - done);
		if (r <= 0)
			return done > 0 ? (long)done : r;
		done += (size_t)r;
	}
	return (long)done;
}

long th_recv(th_stack *s, int fd, void *buf, size_t len)
{
	return receive(s->stack, fd, buf, len);
}

int th_udp_open(th_stack *s, uint16_t port)
{
	return open_listener(s->stack, SOCK_UDP, port);
}

long th_udp_sendto(
    th_stack *s, int fd, const void *data, size_t len, const char *dst_ip, uint16_t dst_port)
{
	struct send_request req = {
	    .data = (unsigned char *)data, .len = len, .dest_port = dst_port};
	parse_ip(dst_ip, req.dest_ip);
	return send_down(s->stack, fd, &req);
}

long th_udp_recvfrom(
    th_stack *s, int fd, void *buf, size_t len, uint8_t src_ip[4], uint16_t *src_port)
{
	return receive_from(s->stack, fd, buf, len, src_ip, src_port);
}

int th_end_send(th_stack *s, int fd)
{
	return tcp_end_send(s->stack, fd);
}

int th_close(th_stack *s, int fd)
{
	return close_socket(s->stack, fd);
}

bool th_conn_lookup(th_stack *s,
		    uint16_t local_port,
		    const char *peer_ip,
		    uint16_t peer_port,
		    struct th_conn_info *out)
{
	struct tcp_conn_id id = {.loc_port = local_port, .extern_port = peer_port};
	memcpy(id.loc_addr, s->ip, 4);
	parse_ip(peer_ip, id.extern_addr);

	struct socket_manager *m = s->stack->sock_manager;
	bool tw = false;
	struct tcp_ipv4_conn *c = query_tcp_conn_hashtable(m->tcp_ipv4_conn_htable, &id);
	if (!c) {
		c = query_tcp_conn_hashtable(m->tcp_ipv4_conn_time_wait_htable, &id);
		tw = c != NULL;
	}
	if (!c)
		return false;

	pthread_mutex_lock(&c->lock);
	memset(out, 0, sizeof(*out));
	out->state = (int)c->state;
	out->in_time_wait_table = tw;
	out->aborted = c->aborted;
	out->iss = c->iss;
	out->irs = c->irs;
	out->snd_una = c->snd_buffer.snd_una;
	out->snd_nxt = c->snd_buffer.snd_nxt;
	out->snd_wnd = c->snd_buffer.snd_wnd;
	out->rcv_nxt = c->rcv_buffer.rcv_nxt;
	out->rcv_wnd = c->rcv_buffer.rcv_wnd;
	out->snd_mss = c->snd_mss;
	out->rcv_mss = c->rcv_mss;
	out->cwnd = c->snd_buffer.cwnd;
	out->ssthresh = c->snd_buffer.ssthresh;
	out->rto_ms = c->rto_interval;
	out->sack_enabled = c->sack_enabled;
	out->ts_enabled = c->ts_enabled;
	out->wscale_enabled = c->wscale_enabled;
	out->retransmit = c->snd_buffer.retransmit;
	out->zero_window_probing = c->is_wndw_probing;
	out->snd_used_bytes = c->snd_buffer.used_bytes;
	out->rcv_contiguous_bytes = c->rcv_buffer.contiguous_bytes;
	pthread_mutex_unlock(&c->lock);

	release_tcp_conn(c);
	return true;
}

// ---- packets and packet ring buffers, for the data-structure tests ----

void *th_pkt_alloc(void)
{
	th_global_init();
	return allocate_pkt();
}

unsigned th_pkt_refcount(void *p)
{
	return atomic_load(&((struct pkt *)p)->ref_count);
}

void th_pkt_retain(void *p)
{
	retain_pkt((struct pkt *)p);
}

void th_pkt_release(void *p)
{
	release_pkt((struct pkt *)p);
}

void *th_ring_create(size_t capacity)
{
	return create_init_pkt_ring_buffer(capacity);
}

bool th_ring_write(void *ring, void *p)
{
	return write_to_pkt_buffer((struct pkt_ring_buffer *)ring, (struct pkt *)p);
}

void *th_ring_read(void *ring)
{
	return read_pkt_buffer((struct pkt_ring_buffer *)ring);
}

void th_ring_destroy(void *ring)
{
	destroy_pkt_ring_buffer((struct pkt_ring_buffer *)ring);
}
