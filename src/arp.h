#pragma once
#include "address_types.h"
#include "pkt_result.h"
#include <stdint.h>
#include <time.h>

#define ARP_REQUEST 1
#define ARP_REPLY 2

#define ETHERNET 1

typedef enum {
	ARP_INCOMPLETE,
	ARP_REACHABLE,
	ARP_STALE, // not implemented, node's last_updated property unused
} arp_node_status;

struct pkt;
struct nw_layer;

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

#ifdef __cplusplus
extern "C" {
#endif

pkt_result receive_arp_up(struct nw_layer *self, struct pkt *packet);
pkt_result send_arp_down(struct nw_layer *self, struct pkt *packet);
void print_arp_header(struct arp_data *arp_header);
void inc_arp_request_to_reply(struct pkt *packet,
			      struct arp_data *header,
			      mac_address_t requested_address);
void complete_arp_table_node(struct arp_table_node *entry, mac_address_t src_mac);
struct arp_table_node *query_arp_table(struct arp_table *table, ipv4_address_t ip);
struct pkt *create_arp_request_for(struct nw_layer *self, ipv4_address_t target_ip);
struct arp_table_node *insert_incomplete_for_ip(struct arp_table *table, ipv4_address_t dest_ip);
pkt_result add_pkt_to_q(struct arp_table_node *node, struct pkt *packet);
void flush_q(struct nw_layer *self, struct arp_table_node *arp_entry);

#ifdef __cplusplus
}
#endif
