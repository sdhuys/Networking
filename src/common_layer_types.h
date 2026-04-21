#pragma once

#define MAX_ETH_FRAME_SIZE 1518 // not supporting vlan tagged frames

#define IPV4 0x0800
#define ARP 0x0806
#define IPV6 0x86DD
#define VLAN 0x8100

#define P_ICMP 1
#define P_TCP 6
#define P_UDP 17

#define IF_NAME "interface"
#define ETH_NAME "ethernet"
#define ARP_NAME "arp"
#define ICMP_NAME "icmp"
#define IPV4_NAME "ipv4"
#define UDP_NAME "udp"
#define TCP_NAME "tcp"
