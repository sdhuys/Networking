#include "stack_constructor.h"
#include "arp.h"
#include "common_layer_types.h"
#include "ethernet.h"
#include "icmp.h"
#include "ipv4.h"
#include "nw_interface.h"
#include "nw_layer.h"
#include "routing_table.h"
#include "socket_manager.h"
#include "sockfd_manager.h"
#include "stack.h"
#include "tap.h"
#include "tcp.h"
#include "tcp_conn_htable.h"
#include "tcp_listener_htable.h"
#include "timer.h"
#include "udp.h"
#include "udp_hashtable.h"
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define TCP_LISTNR_HTBL_SIZE 1024
#define UDP_SCKT_HTBL_SIZE 1024

#define TCP_EST_CONN_HTBL_SIZE 4096
#define TCP_WAIT_CONN_HTBLE_SIZE 2048

struct stack *construct_stack(struct nw_interface *interfaces, size_t if_count)
{
	if (if_count < 1)
		return NULL;
	
	struct nw_layer *interface = malloc(sizeof(struct nw_layer));
	struct nw_layer *eth = malloc(sizeof(struct nw_layer));
	struct nw_layer *arp = malloc(sizeof(struct nw_layer));
	struct nw_layer *ip = malloc(sizeof(struct nw_layer));
	struct nw_layer *icmp = malloc(sizeof(struct nw_layer));
	struct nw_layer *udp = malloc(sizeof(struct nw_layer));
	struct nw_layer *tcp = malloc(sizeof(struct nw_layer));

	struct timer_manager *timer_mgr = create_timer_manager();

	interface->name = IF_NAME;
	interface->send_down = &write_to_interface;
	interface->rcv_up = &send_up_to_ethernet;
	interface->ups_count = 1;
	interface->ups = malloc(interface->ups_count * sizeof(struct nw_layer *));
	interface->ups[0] = eth;
	interface->downs = NULL;
	interface->downs_count = 0;
	struct interface_context *nw_if_context = malloc(sizeof(struct interface_context));
	nw_if_context->if_amount = if_count;
	nw_if_context->interfaces = interfaces;
	interface->context = nw_if_context;

	// assign stack mac address and ip address on same subnet as interface
	static unsigned char stack_mac_addr[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
	static unsigned char stack_ipv4_addr[4];
	set_stack_ipv4_addr(&interfaces[0], stack_ipv4_addr);

	eth->name = ETH_NAME;
	eth->send_down = &send_frame_down;
	eth->rcv_up = &receive_frame_up;
	eth->ups_count = 2;
	eth->downs_count = 1;
	eth->ups = malloc(eth->ups_count * sizeof(struct nw_layer *));
	eth->ups[0] = arp;
	eth->ups[1] = ip;
	eth->downs = malloc(eth->downs_count * sizeof(struct nw_layer *));
	eth->downs[0] = interface;
	struct ethernet_context *eth_context = malloc(sizeof(struct ethernet_context));
	memcpy(eth_context->mac_addr, stack_mac_addr, MAC_ADDR_LEN);
	eth->context = eth_context;

	arp->name = ARP_NAME;
	arp->send_down = &send_arp_down;
	arp->rcv_up = &receive_arp_up;
	arp->ups = NULL;
	arp->ups_count = 0;
	arp->downs_count = 1;
	arp->downs = malloc(arp->downs_count * sizeof(struct nw_layer *));
	arp->downs[0] = eth;
	struct arp_context *arp_ctx = malloc(sizeof(struct arp_context));
	struct arp_table *arp_table = malloc(sizeof(struct arp_table));
	arp_table->head = NULL;
	arp_ctx->arp_table = arp_table;

	memcpy(arp_ctx->ipv4_addr, stack_ipv4_addr, IPV4_ADDR_LEN);
	memcpy(arp_ctx->mac_addr, stack_mac_addr, MAC_ADDR_LEN);
	arp->context = arp_ctx;

	ip->name = IPV4_NAME;
	ip->send_down = &send_ipv4_down;
	ip->rcv_up = &receive_ipv4_up;
	ip->ups_count = 3;
	ip->downs_count = 1;
	ip->ups = malloc(ip->ups_count * sizeof(struct nw_layer *));
	ip->ups[0] = icmp;
	ip->ups[1] = udp;
	ip->ups[2] = tcp;
	ip->downs = malloc(ip->downs_count * sizeof(struct nw_layer *));
	ip->downs[0] = eth;
	struct ipv4_context *ipv4_context = malloc(sizeof(struct ipv4_context));
	ipv4_context->arp_layer = arp;
	ipv4_context->routing_table = create_routing_table(interfaces, if_count);
	memcpy(ipv4_context->stack_ipv4_addr, stack_ipv4_addr, IPV4_ADDR_LEN);
	ip->context = ipv4_context;

	icmp->name = ICMP_NAME;
	icmp->send_down = &send_icmp_down;
	icmp->rcv_up = &receive_icmp_up;
	icmp->ups = NULL;
	icmp->ups_count = 0;
	icmp->downs_count = 1;
	icmp->downs = malloc(icmp->downs_count * sizeof(struct nw_layer *));
	icmp->downs[0] = ip;

	struct socket_manager *socket_manager = malloc(sizeof(struct socket_manager));
	socket_manager->send_down_sock_q = malloc(sizeof(struct socket_h_q));
	socket_manager->send_down_sock_q->head = NULL;
	socket_manager->send_down_sock_q->tail = NULL;
	socket_manager->send_down_sock_q->len = 0;
	pthread_cond_init(&socket_manager->send_down_sock_q->cond, NULL);
	pthread_mutex_init(&socket_manager->send_down_sock_q->lock, NULL);
	socket_manager->udp_ipv4_sckt_htable = create_udp_ipv4_sckt_htable(UDP_SCKT_HTBL_SIZE);
	socket_manager->tcp_ipv4_listener_htable =
	    create_tcp_ipv4_listener_htable(TCP_LISTNR_HTBL_SIZE);
	socket_manager->tcp_ipv4_conn_htable = create_tcp_ipv4_conn_htable(TCP_EST_CONN_HTBL_SIZE);
	socket_manager->tcp_ipv4_conn_time_wait_htable =
	    create_tcp_ipv4_conn_htable(TCP_WAIT_CONN_HTBLE_SIZE);
	socket_manager->sockfd_manager = malloc(sizeof(struct sockfd_manager));
	sockfd_manager_init(socket_manager->sockfd_manager);

	udp->name = UDP_NAME;
	udp->send_down = &send_udp_down;
	udp->rcv_up = &receive_udp_up;
	udp->ups = NULL;
	udp->ups_count = 0;
	udp->downs_count = 1;
	udp->downs = malloc(udp->downs_count * sizeof(struct nw_layer *));
	udp->downs[0] = ip;
	struct udp_context *udp_context = malloc(sizeof(struct udp_context));
	memcpy(udp_context->stack_ipv4_addr, stack_ipv4_addr, IPV4_ADDR_LEN);
	udp_context->sock_manager = socket_manager;
	udp->context = udp_context;

	tcp->name = TCP_NAME;
	tcp->send_down = &send_tcp_down;
	tcp->rcv_up = &receive_tcp_up;
	tcp->ups = NULL;
	tcp->ups_count = 0;
	tcp->downs_count = 1;
	tcp->downs = malloc(tcp->downs_count * sizeof(struct nw_layer *));
	tcp->downs[0] = ip;
	struct tcp_context *tcp_context = malloc(sizeof(struct tcp_context));
	tcp_context->timer_mgr = timer_mgr;
	tcp_context->socket_manager = socket_manager;
	memcpy(tcp_context->stack_ipv4_addr, stack_ipv4_addr, IPV4_ADDR_LEN);
	tcp_context->routing_tbl = ipv4_context->routing_table;
	tcp->context = tcp_context;

	struct stack *stack = malloc(sizeof(struct stack));
	stack->icmp_layer = icmp;
	stack->if_layer = interface;
	memcpy(stack->local_address, stack_ipv4_addr, IPV4_ADDR_LEN);
	stack->sock_manager = socket_manager;
	stack->tcp_layer = tcp;
	stack->udp_layer = udp;
	stack->timer_mgr = timer_mgr;
	return stack;
}
