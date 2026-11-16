#pragma once
#include "address_types.h"

struct nw_layer;
struct socket_manager;
struct timer_manager;
struct routing_table;

struct stack {
	struct nw_layer *if_layer;
	struct nw_layer *udp_layer;
	struct nw_layer *tcp_layer;
	struct nw_layer *icmp_layer;
	struct socket_manager *sock_manager;
	struct timer_manager *timer_mgr; // also part of tcp context
	struct routing_table *routing_table;
};
