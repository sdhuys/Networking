#pragma once
#include "address_types.h"

struct nw_layer;
struct socket_manager;
struct timer_manager;

struct stack {
	struct nw_layer *if_layer;
	struct nw_layer *udp_layer;
	struct nw_layer *tcp_layer;
	struct nw_layer *icmp_layer;
	struct socket_manager *sock_manager;
	struct timer_manager *timer_mgr; // also part of tcp context
	ipv4_address_t local_address; // also part of arp, ipv4, udp and tcp context
};
