// Runs the stack on a TAP device and talks to the Linux kernel's TCP over it.
// Driven by tests/interop/run_interop.sh; needs root (or CAP_NET_ADMIN), Linux only.
//
//   interop_peer echo-server <port> [connections]
//       Listens on <port>, accepts <connections> (default 1) one after another and echoes
//       every byte back until the client closes, then closes its side.
//   interop_peer client <linux-ip> <port> <bytes> [connections]
//       Connects <connections> times to an echo server on Linux, sends <bytes> while
//       reading the echo, and checks the echo matches. Exit code 0 = all matched.
//
// The TAP device is tap0 at 192.168.100.1/24; the stack is 192.168.100.2.
// STACK_DROP_PCT=n makes the stack drop n% of the TCP segments it sends.

#include "api.h"
#include "buffer_pool.h"
#include "fake_env.h"
#include "hash.h"
#include "nw_interface.h"
#include "routing_table.h"
#include "socket_manager.h"
#include "stack.h"
#include "stack_constructor.h"
#include "stack_tx_worker.h"
#include "tap.h"
#include "tcp_conn_htable.h"
#include "timer_worker.h"

#include <arpa/inet.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define TAP_NAME "tap0"
#define STACK_MTU 1500

static struct stack *stack;

// ---------------------------------------------------------------- stack threads

static void *rx_reader(void *arg)
{
	read_from_interface((struct nw_layer *)arg);
	return NULL;
}
static void *rx_processor(void *arg)
{
	process_ingress_q_packets((struct nw_layer *)arg);
	return NULL;
}

static void start_stack(void)
{
	// same interfaces and routes as main.c
	const ipv4_address_t tap_ip = {192, 168, 100, 1};
	const ipv4_address_t stack_ip = {192, 168, 100, 2};
	const ipv4_address_t mask = {255, 255, 255, 0};
	const ipv4_address_t lo_ip = {127, 0, 0, 1};
	const ipv4_address_t lo_mask = {255, 0, 0, 0};
	const mac_address_t lo_mac = {0};
	const mac_address_t stack_mac = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};

	hash_init();
	fake_drop_percent_from_env();

	char name[] = TAP_NAME;
	int fd = tap_setup(name, tap_ip, mask, STACK_MTU);
	if (fd < 0) {
		fprintf(stderr, "interop_peer: TAP setup failed (run as root)\n");
		exit(2);
	}

	static struct nw_interface nw_if[2];
	set_nw_if_struct(
	    &nw_if[0], fd, TAP_NAME, stack_mac, stack_ip, mask, STACK_MTU, tap_transmit, 0);
	set_nw_if_struct(&nw_if[1],
			 -1,
			 "lo",
			 lo_mac,
			 lo_ip,
			 lo_mask,
			 STACK_MTU,
			 loopback_transmit,
			 IF_NOARP | IF_LOOPBACK);
	static struct static_route default_route = {.prefix = {0}, .mask = {0}};
	memcpy(default_route.gateway, tap_ip, IPV4_ADDR_LEN);

	stack = construct_stack(nw_if, 2, &default_route, 1);
	if (!stack) {
		fprintf(stderr, "interop_peer: construct_stack failed\n");
		exit(2);
	}
	init_buffer_pool();

	pthread_t t;
	pthread_create(&t, NULL, rx_reader, stack->if_layer);
	pthread_create(&t, NULL, rx_processor, stack->if_layer);
	pthread_create(&t, NULL, start_timers_loop, stack);
	pthread_create(&t, NULL, stack_transmission_loop, stack);
	fprintf(stderr, "interop_peer: stack up on %s (stack 192.168.100.2)\n", TAP_NAME);
}

// ---------------------------------------------------------------- modes

// Connections still in the main table, i.e. not yet CLOSED or in TIME_WAIT.
static size_t live_connections(void)
{
	struct tcp_ipv4_conn_htable *t = stack->sock_manager->tcp_ipv4_conn_htable;
	size_t n = 0;
	for (uint32_t b = 0; b < t->buckets_amount; b++) {
		pthread_mutex_lock(&t->bucket_locks[b]);
		for (struct tcp_ipv4_conn_htbl_node *e = t->buckets[b]; e; e = e->next)
			n++;
		pthread_mutex_unlock(&t->bucket_locks[b]);
	}
	return n;
}

// The data an app hands to send_down is only buffered. Exiting the process right after
// the last send throws away whatever the stack hasn't delivered yet, which under loss can
// be most of the send buffer. Wait until every connection has finished its close.
static void wait_for_connections_to_close(int timeout_s)
{
	for (int i = 0; i < timeout_s * 10 && live_connections() > 0; i++)
		usleep(100 * 1000);
	if (live_connections() > 0)
		fprintf(stderr, "interop_peer: connections still open after %d s\n", timeout_s);
	sleep(1); // the final ACKs
}

static long send_all(int fd, const unsigned char *d, size_t n)
{
	size_t done = 0;
	while (done < n) {
		struct send_request req = {.data = (unsigned char *)d + done, .len = n - done};
		int r = send_down(stack, fd, &req);
		if (r <= 0)
			return r;
		done += (size_t)r;
	}
	return (long)done;
}

static int echo_server(uint16_t port, int conns)
{
	int l = open_listener(stack, SOCK_TCP, port);
	if (l < 0) {
		fprintf(stderr, "open_listener: %d\n", l);
		return 1;
	}
	printf("READY\n");
	fflush(stdout);
	static unsigned char buf[65536];
	for (int i = 0; i < conns; i++) {
		int c = accept_connection(stack, l);
		if (c < 0) {
			fprintf(stderr, "accept: %d\n", c);
			return 1;
		}
		long total = 0, r;
		while ((r = receive(stack, c, buf, sizeof buf)) > 0) {
			if (send_all(c, buf, (size_t)r) != r) {
				fprintf(stderr, "echo: send failed\n");
				return 1;
			}
			total += r;
		}
		if (r < 0) {
			fprintf(stderr, "echo: receive returned %ld after %ld bytes\n", r, total);
			return 1;
		}
		tcp_end_send(stack, c);
		close_socket(stack, c);
		printf("ECHOED %ld\n", total);
		fflush(stdout);
	}
	wait_for_connections_to_close(300);
	return 0;
}

struct sender_args {
	int fd;
	const unsigned char *data;
	size_t len;
	long result;
};

static void *sender(void *arg)
{
	struct sender_args *a = arg;
	a->result = send_all(a->fd, a->data, a->len);
	tcp_end_send(stack, a->fd);
	return NULL;
}

static int client(const char *ip, uint16_t port, size_t bytes, int conns)
{
	unsigned char *data = malloc(bytes), *got = malloc(bytes + 1);
	uint32_t x = (uint32_t)time(NULL) | 1;
	for (size_t i = 0; i < bytes; i++) {
		x ^= x << 13;
		x ^= x >> 17;
		x ^= x << 5;
		data[i] = (unsigned char)x;
	}
	ipv4_address_t dst;
	inet_pton(AF_INET, ip, dst);
	sleep(2); // tap0 exists now: give the Linux echo server time to bind to it
	int failures = 0;
	for (int i = 0; i < conns; i++) {
		int fd = tcp_connect(stack, (uint16_t)(40000 + i), port, dst);
		if (fd < 0) {
			fprintf(stderr, "connect: %d\n", fd);
			return 1;
		}
		struct sender_args a = {.fd = fd, .data = data, .len = bytes};
		pthread_t t;
		pthread_create(&t, NULL, sender, &a);
		size_t have = 0;
		long r;
		while ((r = receive(stack, fd, got + have, bytes + 1 - have)) > 0)
			have += (size_t)r;
		pthread_join(t, NULL);
		bool ok = r == 0 && have == bytes && a.result == (long)bytes
			  && memcmp(got, data, bytes) == 0;
		printf("CONN %d %s sent=%ld echoed=%zu last=%ld\n",
		       i,
		       ok ? "OK" : "MISMATCH",
		       a.result,
		       have,
		       r);
		fflush(stdout);
		failures += !ok;
		close_socket(stack, fd);
	}
	wait_for_connections_to_close(60);
	return failures ? 1 : 0;
}

int main(int argc, char **argv)
{
	if (argc < 3) {
		fprintf(
		    stderr,
		    "usage: %s echo-server <port> [conns] | client <ip> <port> <bytes> [conns]\n",
		    argv[0]);
		return 2;
	}
	alarm(600); // last resort; run_interop.sh has its own per-case timeout
	start_stack();
	if (strcmp(argv[1], "echo-server") == 0)
		return echo_server((uint16_t)atoi(argv[2]), argc > 3 ? atoi(argv[3]) : 1);
	if (strcmp(argv[1], "client") == 0 && argc >= 5)
		return client(argv[2],
			      (uint16_t)atoi(argv[3]),
			      (size_t)atol(argv[4]),
			      argc > 5 ? atoi(argv[5]) : 1);
	fprintf(stderr, "bad arguments\n");
	return 2;
}
