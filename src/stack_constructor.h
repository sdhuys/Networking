#pragma once
#include "arp.h"
#include "ethernet.h"
#include "icmp.h"
#include "ipv4.h"
#include "routing_table.h"
#include "tap.h"
#include "tcp.h"
#include "udp.h"
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

struct stack_t construct_stack(int fd, char *if_name);
void set_net_if_struct(int fd, char *if_name, struct nw_interface_t *n_if);
void set_stack_ipv4_addr(struct nw_interface_t *n_if, ipv4_address stack_ip_addr);

#ifdef __cplusplus
}
#endif
