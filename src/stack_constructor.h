#pragma once
#include "arp.h"
#include "ethernet.h"
#include "icmp.h"
#include "ipv4.h"
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
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#define TCP_LISTNR_HTBL_SIZE 1024
#define UDP_SCKT_HTBL_SIZE 1024

#define TCP_EST_CONN_HTBL_SIZE 4096
#define TCP_WAIT_CONN_HTBLE_SIZE 1280

#ifdef __cplusplus
extern "C" {
#endif

struct stack_t construct_stack(int fd, char *if_name);
void set_net_if_struct(int fd, char *if_name, struct nw_interface_t *n_if);
void set_stack_ipv4_addr(struct nw_interface_t *n_if, ipv4_address stack_ip_addr);

#ifdef __cplusplus
}
#endif
