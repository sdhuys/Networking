#include "app.h"
#include "buffer_pool.h"
#include "hash.h"
#include "nw_interface.h"
#include "ping_test.h"
#include "pkt.h"
#include "routing_table.h"
#include "stack.h"
#include "stack_constructor.h"
#include "stack_tx_worker.h"
#include "tap.h"
#include "timer_worker.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define STACK_MTU 1500 // must fit PKT_SIZE - Ethernet header
_Static_assert(STACK_MTU + 14 <= PKT_SIZE, "MTU larger than a packet buffer");

void *start_client_app_wrapper(void *arg)
{
	struct stack *stack = (struct stack *)arg;
	client_app(stack);
	return NULL;
}

void *start_server_app_wrapper(void *arg)
{
	struct stack *stack = (struct stack *)arg;
	server_app(stack);
	return NULL;
}

void *read_from_interface_wrapper(void *arg)
{
	struct nw_layer *tap = (struct nw_layer *)arg;
	read_from_interface(tap);
	return NULL;
}

int main()
{
	hash_init();
	int tap_fd;
	const ipv4_address_t tap_ip_addr = {192, 168, 100, 1};
	const ipv4_address_t stack_ip_addr = {192, 168, 100, 2};
	const ipv4_address_t subnet_mask = {0xFF, 0xFF, 0xFF, 0};
	const ipv4_address_t loopback_addr = {127, 0, 0, 1};
	const ipv4_address_t loopback_mask = {0xFF, 0, 0, 0};
	const mac_address_t loopback_mac = {0};
	const mac_address_t stack_mac_addr = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};

	struct static_route static_routes[] = {{.prefix = {0}, .mask = {0}}};
	memcpy(&static_routes[0].gateway, &tap_ip_addr, IPV4_ADDR_LEN);
	size_t static_routes_count = 1;

	if ((tap_fd = tap_setup("tap0", tap_ip_addr, subnet_mask, STACK_MTU)) < 0)
		return 1;
	struct nw_interface *nw_if = calloc(2, sizeof(struct nw_interface));
	set_nw_if_struct(&nw_if[0],
			 tap_fd,
			 "tap0",
			 stack_mac_addr,
			 stack_ip_addr,
			 subnet_mask,
			 STACK_MTU,
			 tap_transmit,
			 0);
	set_nw_if_struct(&nw_if[1],
			 -1,
			 "loopback",
			 loopback_mac,
			 loopback_addr,
			 loopback_mask,
			 STACK_MTU,
			 loopback_transmit,
			 IF_NOARP | IF_LOOPBACK);
	size_t if_count = 2;

	struct stack *stack = construct_stack(nw_if, if_count, static_routes, static_routes_count);
	if (!stack)
		return 2;

	init_buffer_pool();

	struct nw_layer *tap = stack->if_layer;
	pthread_t interface_reader_tid;
	pthread_t timer_tid;
	pthread_t client_app_tid;
	pthread_t server_app_tid;
	pthread_t stack_tx_tid;
	// pthread_t ping_testid;

	// pthread_create(&ping_testid, NULL, ping_test, (void *)stack);
	pthread_create(&interface_reader_tid, NULL, read_from_interface_wrapper, (void *)tap);
	pthread_create(&timer_tid, NULL, start_timers_loop, (void *)stack);
	pthread_create(&client_app_tid, NULL, start_client_app_wrapper, (void *)stack);
	pthread_create(&server_app_tid, NULL, start_server_app_wrapper, (void *)stack);
	pthread_create(&stack_tx_tid, NULL, stack_transmission_loop, (void *)stack);

	process_ingress_q_packets(tap);

	return 0;
}
