#pragma once
#include "address_types.h"
#include "tcp_common_types.h"
#include <net/if.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

// ===== Definitions & Constants =====

#define IPV4_V 4
#define IPV4_HEADER_NO_OPTIONS_LEN 5 // length in 32bits (5 = 5 * 32 bits)
#define IPV4_TTL_DEFAULT 64

#define ETHERNET 1

#define ARP_REQUEST 1
#define ARP_REPLY 2

#define MAX_ETH_FRAME_SIZE 1518 // not supporting vlan tagged frames
#define ALIGN_PADDING ((MAX_ETH_FRAME_SIZE / 64) + 1) * 64
#define PKT_SIZE MAX_ETH_FRAME_SIZE + ALIGN_PADDING

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

// ===== Common Types =====

typedef uint16_t ether_type;

// ===== Result Codes ====
// multiples of 10 signify packet sent, already released
typedef enum {
	SENT = 10,
	ARP_REPLY_SENT = 20,
	SYN_COOKIE_SENT = 40,
	TCP_IMMEDIATE_ACK_SNT = 50,
	TCP_SEG_OUT_WNDW_RNG_ACK_SNT = -400,
	INC_RST_CHALL_ACK_SENT = -410,
	TCP_ACK_OUT_OF_SYNC = -420,

	ARP_TABLE_UPDATED_Q_FLUSHED = 25,
	PACKET_QUEUED = 26,
	UDP_WRITTEN_TO_RCV_BUFF = 41,

	SYN_COOKIE_CONN_CREATED = 43,
	CONN_CREATED_SYN_ACK_TO_SND_BUFFER = 44,
	RCOV_SYN_ACK_TO_SND_BUFFER = 45,
	TCP_SIMULTANEOUS_OPEN = 46,
	INC_RST_CONN_DEAD = 47,
	TCP_SEG_PROCESSED = 61,
	ICMP_ECHO_REPLY_RCVD = 35,

	WRITE_ERROR = -101,
	FRAME_TARGET_NOT_RELEVANT = -201,
	ETHERTYPE_NOT_SUPPORTED = -202,
	ARP_HW_TYPE_NOT_SUPPORTED = -251,
	ARP_PRTCL_TYPE_NOT_SUPPORTED = -252,
	ARP_RQST_TARGET_NOT_RELEVANT = -253,
	ARP_REPLY_NOT_RQSTD = -254,
	ARP_UNKNOWN_OPERATION = -255,
	ARP_MALFORMED = -256,
	IP_VERSION_MISMATCH = -301,
	IP_FRAGMENTATION_NOT_SUPPORTED = -302,
	IP_OPTIONS_NOT_SUPPORTED = -303,
	IP_CHECKSUM_ERROR = -304,
	IP_DEST_NOT_RELEVANT = -305,
	IP_HDR_TRANSPORT_PROT_NOT_SUPPORTED = -306,
	IP_NO_ROUTE_FOUND = -307,
	ICMP_CHECKSUM_ERROR = -351,
	ICMP_TYPE_NOT_SUPPORTED = -352,
	UDP_CHECKSUM_ERROR = -401,
	UDP_HEADER_MALFORMED = -402,
	UDP_PORT_NO_LISTENER = -403,
	UDP_SOCKET_CLOSED = -404,
	TCP_HEADER_MALFORMED = -411,
	TCP_BOGUS_FLAGS = -412,
	TCP_CHECKSUM_ERROR = -413,
	TCP_OPTIONS_MALFORMED = -414,
	TCP_SEG_DUPLICATE = -415,
	TCP_SEG_OUT_OF_WNDW_RANGE = -416,
	TCP_NO_CONNECTION = -417,
	TCP_CONN_CREATION_ERROR = -418,
	TCP_SYN_COOKIE_EXPIRED = -419,
	TCP_SYN_COOKIE_INVALID = -420,
	SYN_COOKIE_UNROUTABLE = -421,
	SYN_COOKIE_OUT_OF_MEMORY = -422,
	RST_UNEXPECTED_SYN = -423,
	INVALID_RST_DROPPED = -424,
	TCP_TIME_WAIT_DROPPED = -425,

	RING_BUFFER_FULL = -501,

	LAYER_NAME_NOT_FOUND = -2,
	NOT_IMPLEMENTED_YET = -1
} pkt_result;

// ===== Packet Structure =====
struct pkt {
	unsigned char *data;
	size_t offset; // Offset to the start of the current layer's header
	size_t len;    // Packet length from current offset (current layer's length)

	pthread_mutex_t lock;
	uint16_t pool_index; // for debugging
	uint8_t ref_count;

	int if_index;
	ether_type ethertype;
	uint8_t protocol;
	mac_address_t dest_mac;

	ipv4_address_t src_ip;
	ipv4_address_t dest_ip;

	// TRANSPORT LAYER metadata
	// apart from src and dest ports for UDP, these fields are only ever used to store metadata
	// for outgoing packets
	uint16_t src_port;
	uint16_t dest_port;
	uint32_t tcp_seq;
	uint32_t tcp_ack;
	uint8_t tcp_flags;
	uint16_t rcv_window;
	struct tcp_options *tcp_options;
	struct route *route;
};

// ===== General Network Layer Structure =====
struct nw_layer {
	char *name;
	pkt_result (*send_down)(struct nw_layer *self, struct pkt *packet);
	pkt_result (*rcv_up)(struct nw_layer *self, struct pkt *packet);
	struct nw_layer **ups;
	struct nw_layer **downs;
	size_t ups_count;
	size_t downs_count;
	void *context;
};

// ===== Network Interface =====
// set as the context of interface nw_layer
struct interface_context {
	struct nw_interface *interfaces;
	size_t if_amount;
	struct timer_manager *rx_timer_mgr; // rx thread timers (delayed ACKS, ARP timeouts, etc)
};

// ===== Ethernet Layer =====
struct ethernet_context {
	mac_address_t mac_addr;
};

struct ethernet_header {
	mac_address_t dest_mac;
	mac_address_t src_mac;
	ether_type ethertype;
} __attribute__((packed));

// ===== ARP Layer =====
typedef enum {
	ARP_INCOMPLETE,
	ARP_REACHABLE,
	ARP_STALE, // not implemented, node's last_updated property unused
} arp_node_status;

struct arp_table {
	struct arp_table_node *head;
};

struct arp_table_node {
	ipv4_address_t ipv4_addr;
	mac_address_t mac_addr;
	arp_node_status status;
	time_t last_updated;
	struct queue_entry *pending_packets;
	struct queue_entry *pending_tail;
	struct arp_table_node *next;
};

struct queue_entry {
	struct pkt *packet;
	struct queue_entry *next;
};

struct arp_context {
	ipv4_address_t ipv4_addr;
	mac_address_t mac_addr;
	struct arp_table *arp_table;
};

struct arp_data {
	uint16_t hw_type;
	uint16_t proto_type;
	unsigned char hw_addr_len;
	unsigned char proto_addr_len;
	uint16_t operation;
	mac_address_t src_mac;
	ipv4_address_t src_ip;
	mac_address_t target_mac;
	ipv4_address_t target_ip;
} __attribute__((packed));

// ===== IPv4 Layer =====

struct ipv4_context {
	struct nw_layer *arp_layer;
	ipv4_address_t stack_ipv4_addr;
	struct routing_table *routing_table;
};

struct ipv4_header {
	// upper 4 bits = version (4 for ipv4)
	// lower 4 bits = internet header-length (unit = 32bits, min value = 5)
	unsigned char version_ihl;
	// upper 6 bits = dscp, lower 2 bits = ecn. IGNORED, NOT SUPPORTED!
	unsigned char dscp_ecn;
	uint16_t total_length;
	uint16_t id;
	// upper 3 bits = flags => first = reserved, second = don't fragment, third
	// = more fragments lower 13 bits = fragment offset
	uint16_t flags_fragment_offset;
	unsigned char ttl;
	unsigned char protocol;
	uint16_t header_checksum;
	ipv4_address_t src_ip;
	ipv4_address_t dest_ip;
} __attribute__((packed));

struct ipv4_pseudo_header {
	ipv4_address_t src_ip;
	ipv4_address_t dest_ip;
	uint8_t padding;
	uint8_t protocol;
	uint16_t len;
} __attribute__((packed));

//// TRANSPORT LAYERS ////

// UDP LAYER
struct udp_context {
	ipv4_address_t stack_ipv4_addr;
	struct socket_manager *sock_manager;
};

struct udp_header {
	uint16_t src_port;
	uint16_t dest_port;
	uint16_t length;
	uint16_t checksum;
} __attribute__((packed));

// Checksum data
struct checksum_chunk {
	const void *data;
	size_t len;
};

// STACK: contains everything for stack rcv + snd and app rcv + snd
struct stack {
	struct nw_layer *if_layer;
	struct nw_layer *udp_layer;
	struct nw_layer *tcp_layer;
	struct nw_layer *icmp_layer;
	struct socket_manager *sock_manager;
	struct timer_manager *tx_timer_mgr;
	ipv4_address_t local_address;
};

// App send request
struct send_request {
	unsigned char *data;
	size_t len;
	ipv4_address_t dest_ip; // optional, only for UDP
	uint16_t dest_port;	// optional, only for UDP
};
