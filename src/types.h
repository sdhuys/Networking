#pragma once
#include <net/if.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

// ===== Definitions & Constants =====
#define MAC_ADDR_LEN 6
#define IPV4_ADDR_LEN 4

#define IPV4_V 4
#define IPV4_HEADER_NO_OPTIONS_LEN 5 // length in 32bits (5 = 5 * 32 bits)
#define IPV4_TTL_DEFAULT 64

#define ETHERNET 1

#define ARP_REQUEST 1
#define ARP_REPLY 2

#define MAX_ETH_FRAME_SIZE 1518 // not supporting vlan tagged frames

#define IPV4 0x0800
#define ARP 0x0806
#define IPV6 0x86DD
#define VLAN 0x8100

#define P_ICMP 1
#define P_TCP 6
#define P_UDP 17

#define ECHO_REPLY 0
#define DESTINATION_UNREACHABLE 3
#define ECHO_REQUEST 8

#define TAP_NAME "tap0"
#define ETH_NAME "ethernet"
#define ARP_NAME "arp"
#define ICMP_NAME "icmp"
#define IPV4_NAME "ipv4"
#define UDP_NAME "udp"
#define TCP_NAME "tcp"

#define UDP_SCKT_HTBL_SIZE 128	// buckets for listener entries
#define TCP_SCKT_HTBL_SIZE 1024 // buckets for listener entries + multiple connections per etry
#define RING_BUFF_SIZE 1024

#define GOLDEN_RATIO_32 2654435761U

extern const unsigned char IPV4_BROADCAST_MAC[MAC_ADDR_LEN];
extern const unsigned char IPV4_BROADCAST_IP[IPV4_ADDR_LEN];

// ===== Common Types =====
typedef unsigned char mac_address[MAC_ADDR_LEN];
typedef unsigned char ipv4_address[IPV4_ADDR_LEN];
typedef uint16_t ether_type;

// ===== Result Codes ====
typedef enum {
	SENT = 10,
	ARP_TABLE_UPDATED_Q_FLUSHED = 25,
	PACKET_QUEUED = 26,
	SENT_UP_TO_APPLICATION = 40,

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
	UDP_PORT_NO_LISTENER = -402,
	UDP_SOCKET_CLOSED = -403,

	RING_BUFFER_FULL = -501,

	LAYER_NAME_NOT_FOUND = -2,
	NOT_IMPLEMENTED_YET = -1
} pkt_result;

typedef enum {
	TCP_CLOSED = 0,	  // No connection state
	TCP_LISTEN,	  // Waiting for a connection request from any remote TCP
	TCP_SYN_SENT,	  // Sent SYN, waiting for SYN+ACK
	TCP_SYN_RECEIVED, // Received SYN, sent SYN+ACK
	TCP_ESTABLISHED,  // Connection established
	TCP_FIN_WAIT_1,	  // Application closed, sent FIN, waiting for ACK
	TCP_FIN_WAIT_2,	  // Received ACK of FIN, waiting for remote FIN
	TCP_CLOSE_WAIT,	  // Received FIN from remote, waiting for application close
	TCP_CLOSING,	  // Simultaneous close, sent FIN, waiting for ACK of FIN
	TCP_LAST_ACK,	  // Waiting for ACK of our FIN after close
	TCP_TIME_WAIT	  // Waiting for 2*MSL (maximum segment lifetime) before releasing
} tcp_state_t;

// ===== Packet Structure =====
struct pkt_t {
	unsigned char *data; // Only modified once we go back down the stack
	size_t offset;	     // Offset to the start of the current layer's header
	uint16_t len;	     // Packet length from current offset (current layer's length)
	uint8_t ref_count;
	int intrfc_indx;
	ether_type ethertype;
	uint8_t protocol;
	mac_address dest_mac;
	ipv4_address src_ip;
	ipv4_address dest_ip;
	uint16_t src_port;
	uint16_t dest_port;
};

// ===== General Network Layer Structure =====
struct nw_layer_t {
	char *name;
	pkt_result (*send_down)(struct nw_layer_t *self, struct pkt_t *packet);
	pkt_result (*rcv_up)(struct nw_layer_t *self, struct pkt_t *packet);
	struct nw_layer_t **ups;
	struct nw_layer_t **downs;
	size_t ups_count;
	size_t downs_count;
	void *context;
};

// ===== Network Interface =====
// set as the context of interface nw_layer
struct interface_context_t {
	struct nw_interface_t *interfaces;
	size_t if_amount;
};

struct nw_interface_t {
	char name[IFNAMSIZ];
	int fd;
	uint32_t ipv4_addr;   // network byte order
	uint32_t subnet_mask; // network byte order
	mac_address mac_addr;
	uint8_t mtu;
};

// ===== Ethernet Layer =====
struct ethernet_context_t {
	mac_address mac_addr;
};

struct ethernet_header_t {
	mac_address dest_mac;
	mac_address src_mac;
	ether_type ethertype;
} __attribute__((packed));

// ===== ARP Layer =====
typedef enum {
	ARP_INCOMPLETE,
	ARP_REACHABLE,
	ARP_STALE, // not implemented, node's last_updated property unused
} arp_node_status_t;

struct arp_table_t {
	struct arp_table_node_t *head;
};

struct arp_table_node_t {
	ipv4_address ipv4_addr;
	mac_address mac_addr;
	arp_node_status_t status;
	time_t last_updated;
	struct queue_entry_t *pending_packets;
	struct queue_entry_t *pending_tail;
	struct arp_table_node_t *next;
};

struct queue_entry_t {
	struct pkt_t *packet;
	struct queue_entry_t *next;
};

struct arp_context_t {
	ipv4_address ipv4_addr;
	mac_address mac_addr;
	struct arp_table_t *arp_table;
};

struct arp_data_t {
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
} route_type_t;

struct route_t {
	uint32_t prefix;      // network byte order
	uint32_t subnet_mask; // network byte order
	uint8_t prefix_len;   // CIDR mask (0–32)
	uint8_t mtu;	      // max transmission unit
	route_type_t type;
	uint32_t gateway; // valid only if type == ROUTE_VIA
	uint32_t iface_id;
};

struct ipv4_context_t {
	struct nw_layer_t *arp_layer;
	ipv4_address stack_ipv4_addr;
	struct nw_interface_t *nw_if;
	struct route_t *routing_table;
	size_t routes_amount;
};

struct ipv4_header_t {
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

struct ipv4_pseudo_header_t {
	ipv4_address src_ip;
	ipv4_address dest_ip;
	uint8_t padding;
	uint8_t protocol;
	uint16_t len;
} __attribute__((packed));

// ICMP LAYER
struct icmp_context_t {
};

struct icmp_header_t {
	unsigned char type;
	unsigned char code;
	uint16_t checksum;
	uint32_t var_rest_of_header;
} __attribute__((packed));

//// TRANSPORT LAYERS ////
// RING BUFFER
struct ring_buffer_t {
	struct pkt_t *packets[RING_BUFF_SIZE];
	uint32_t head;
	uint32_t tail;
};

// UDP LAYER
struct udp_context_t {
	ipv4_address stack_ipv4_addr;
	struct socket_manager_t *sock_manager;
};

struct udp_header_t {
	uint16_t src_port;
	uint16_t dest_port;
	uint16_t length;
	uint16_t checksum;
} __attribute__((packed));

typedef enum { LISTENING, CLOSED } udp_socket_state_t;

struct udp_ipv4_socket_t {
	uint16_t local_port;
	struct ring_buffer_t *rcv_buffer; // stack writes, app consumes
	struct ring_buffer_t *snd_buffer; // app writes, stack consumes
	udp_socket_state_t state;
	uint8_t ref_count;
	bool queued_for_rcv;
	bool queued_for_snd;
	pthread_mutex_t lock;
};

struct udp_ipv4_sckt_htable_node_t {
	struct udp_ipv4_socket_t *socket;
	struct udp_ipv4_sckt_htable_node_t *next;
};

struct udp_ipv4_sckt_htable_t {
	struct udp_ipv4_sckt_htable_node_t **buckets;
	uint16_t buckets_amount;
	pthread_mutex_t *bucket_locks; // One lock per bucket
};

// TCP LAYER
struct tcp_context_t {
	ipv4_address stack_ipv4_addr;
	struct socket_manager_t *socket_manager;
};

struct tcp_ipv4_socket_t {
	ipv4_address local_addr;
	ipv4_address extern_addr;
	uint16_t local_port;
	uint16_t extern_port;
	struct ring_buffer_t rcv_buffer; // stack writes, app consumes
	struct ring_buffer_t snd_buffer; // app writes, stack consumes
};

struct tcp_ipv4_sckt_node_t {
	struct tcp_ipv4_socket_t *socket;
	struct tcp_ipv4_sckt_node_t *next;
};

struct tcp_ipv4_socket_htable_t {
	struct tcp_ipv4_sckt_node_t **buckets;
	uint8_t buckets_amount;
	// add add()
	// add remove()
	// add query_connected()
	// add query_listening()
};

// Checksum data
struct checksum_chunk {
	const void *data;
	size_t len;
};

// Socket manager
struct socket_manager_t {
	struct tcp_ipv4_socket_htable_t *tcp_ipv4_sckt_htable;
	struct udp_ipv4_sckt_htable_t *udp_ipv4_sckt_htable;
	struct socket_h_q_t *send_down_sock_q;	// app writes, stack reads
	struct socket_h_q_t *receive_up_sock_q; // stack writes, app reads
};

// STACK: contains everything for stack rcv + snd and app rcv + snd
struct stack_t {
	struct nw_layer_t *if_layer;
	struct socket_manager_t *sock_manager;
};

// App send request
struct send_request_t {
	unsigned char *data;
	size_t len;
	ipv4_address dest_ip; // optional, only for UDP
	uint16_t dest_port;   // optional, only for UDP
};

// Protocol agnostic socket operations
struct socket_ops_t {
	bool (*is_rcv_queued)(void *sock);
	void (*set_rcv_queued)(void *sock, bool);

	bool (*is_snd_queued)(void *sock);
	void (*set_snd_queued)(void *sock, bool);

	void (*retain)(void *sock);
	void (*release)(void *sock);

	bool (*write_to_snd_buffer)(void *sock, struct send_request_t req);
	struct pkt_t *(*read_rcv_buffer)(void *sock);
};

// Transport-protocol-agnostic socket handle
typedef enum { SOCK_UDP, SOCK_TCP } socket_type_t;

struct socket_handle_t {
	void *sock;
	socket_type_t type;		// for debugging/logging
	const struct socket_ops_t *ops; // should contain all type-specific actions
};

// Socket handle queue
struct socket_h_q_t {
	struct socket_h_q_node_t *head;
	struct socket_h_q_node_t *tail;
	pthread_mutex_t lock;
};

struct socket_h_q_node_t {
	struct socket_handle_t socket;
	struct socket_h_q_node_t *next;
};
