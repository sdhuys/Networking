#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

// ===== Definitions & Constants =====
#define MAC_ADDR_LEN 6
#define IPV4_ADDR_LEN 4

#define IPV4_V 4
#define IPV4_HEADER_NO_OPTIONS_LEN 5 // means 5 * 32 bits header length
#define IPV4_TTL 64

#define ETHERNET 1

#define ARP_REQUEST 1
#define ARP_REPLY 2

#define MAX_ETH_FRAME_SIZE 1518 // not supporting vlan tagged frames

#define IPV4 0x0800
#define ARP 0x0806
#define IPV6 0x86DD
#define VLAN 0x8100

#define ICMP 1
#define IGMP 2
#define TCP 6
#define UDP 11
#define ENCAP 41
#define OSPF 89
#define SCTP 132

#define ECHO_REPLY 0
#define DESTINATION_UNREACHABLE 3
#define ECHO_REQUEST 8

#define TAP_NAME "tap"
#define ETH_NAME "ethernet"
#define ARP_NAME "arp"
#define ICMP_NAME "icmp"
#define IPV4_NAME "ipv4"
#define UDP_NAME "udp"
#define TCP_NAME "tcp"

extern const unsigned char IPV4_BROADCAST_MAC[MAC_ADDR_LEN];
extern const unsigned char STACK_IPV4_ADRR[4];
extern const unsigned char DUMMY_MAC_ADDR[6];

// ===== Common Types =====
typedef unsigned char mac_address[MAC_ADDR_LEN];
typedef unsigned char ipv4_address[IPV4_ADDR_LEN];
typedef uint16_t protocol_type;

// ===== Result Codes ====
typedef enum {
	SENT = 10,
	ARP_TABLE_UPDATED_Q_FLUSHED = 25,
	PACKET_QUEUED = 26,

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
	IP_HDR_UNKNOWN_TRANSPORT_PROT = -307,
	ICMP_CHECKSUM_ERROR = -351,
	ICMP_TYPE_NOT_SUPPORTED = -352,

	LAYER_NAME_NOT_FOUND = -2,
	NOT_IMPLEMENTED_YET = -1
} pkt_result;

// ===== Packet Structures =====
struct pkt_metadata {

	protocol_type ethertype;
	mac_address dest_mac;

	ipv4_address src_ip;
	// stack's API for applications to send packets out should set this
	ipv4_address dest_ip;
};

struct pkt {
	unsigned char *data; // Only modified once we go back down the stack
	size_t len;	     // Packet length from current offset (current layer's length)
	size_t offset;	     // Offset to the start of the current layer's header within
			     // data, no need to strip headers and copy
	uint8_t ref_count;
	struct pkt_metadata metadata;
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
struct net_if {
	char *name;
	int fd;
	ipv4_address ip_addr;
	ipv4_address netmask;
	mac_address mac_addr;
	uint8_t mtu;
};

// ===== Interface Layer =====
struct interface_context {
	struct net_if n_if;
};

// ===== Ethernet Layer =====
struct ethernet_context {
	mac_address mac_addr;
};

struct ethernet_header {
	mac_address dest_mac;
	mac_address src_mac;
	protocol_type ethertype;
} __attribute__((packed));

// ===== ARP Layer =====
enum arp_node_status {
	ARP_INCOMPLETE,
	ARP_REACHABLE,
	ARP_STALE, // not implemented, node's last_updated property unused
};

struct arp_table {
	struct arp_table_node *head;
};

struct arp_table_node {
	ipv4_address ipv4_addr;
	mac_address mac_addr;
	enum arp_node_status status;
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
	ipv4_address ipv4_addr;
	mac_address mac_addr;
	struct arp_table *arp_table;
};

struct arp_data {
	uint16_t hw_type;
	uint16_t proto_type;
	unsigned char hw_addr_len;
	unsigned char proto_addr_len;
	uint16_t operation;
	mac_address src_mac;
	ipv4_address src_ip;
	mac_address target_mac;
	ipv4_address target_ip;
} __attribute__((packed));

// ===== IPv4 Layer =====

typedef enum {
	ROUTE_ONLINK, // destination is directly reachable
	ROUTE_VIA     // send via gateway
} route_type;

struct route {
	uint32_t prefix;    // network byte order
	uint8_t prefix_len; // CIDR mask (0–32)
	uint8_t mtu;	    // max transmission unit
	route_type type;
	uint32_t gateway;  // valid only if type == ROUTE_VIA
	uint32_t iface_id; // which interface to send on (NOT IMPLEMENTED, HARDCODED
			   // ONLY 1 INTERFACE)
};

struct ipv4_context {
	struct nw_layer *arp_layer;
	ipv4_address ipv4_addr;
	ipv4_address subnet_mask;
	struct route *routing_table;
	size_t routes_amount;
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
	ipv4_address src_ip;
	ipv4_address dest_ip;
} __attribute__((packed));

// ICMP LAYER
struct icmp_context {
};

struct icmp_header {
	unsigned char type;
	unsigned char code;
	uint16_t checksum;
	uint32_t var_rest_of_header;
} __attribute__((packed));