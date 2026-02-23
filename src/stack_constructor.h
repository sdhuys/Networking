#pragma once
#include "arp.h"
#include "ethernet.h"
#include "icmp.h"
#include "ipv4.h"
#include "nw_interface.h"
#include "routing_table.h"
#include "socket_manager.h"
#include "sockfd_manager.h"
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

#ifdef __cplusplus
extern "C" {
#endif

struct stack construct_stack(struct nw_interface *interface_array, size_t if_count);

#ifdef __cplusplus
}
#endif
