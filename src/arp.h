#pragma once
#include "address_types.h"
#include "pkt_result.h"
#include <pthread.h>
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
struct route;

struct arp_table {
	struct arp_table_node *head;
	pthread_mutex_t lock;
	size_t node_pending_pkt_cap;
};

struct arp_table_node {
	ipv4_address_t ipv4_addr;
	mac_address_t mac_addr;
	arp_node_status status;
	time_t last_updated;
	struct pkt **pending_pkts;
	size_t pending_packets_count;
	struct arp_table_node *next;
};

struct arp_context {
	struct nw_interface *nw_ifs;
	size_t if_count;
	struct arp_table *arp_table;
	struct timer_manager *timer_mgr;
};

struct arp_data {
	uint16_t hw_type;
	uint16_t proto_type;
	unsigned char hw_addr_len;
	unsigned char prtcl_addr_len;
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
struct pkt *create_arp_request_for(struct nw_layer *self,
				   ipv4_address_t target_ip,
				   struct route *route);
struct arp_table_node *insert_incomplete_for_ip(struct arp_table *table, ipv4_address_t dest_ip);
pkt_result add_pkt_to_q(struct arp_table *table, struct arp_table_node *node, struct pkt *p);
void flush_q(struct nw_layer *self, struct arp_table_node *arp_entry);
struct arp_table *create_arp_table(size_t pending_packets_max);
struct arp_table_node *create_arp_node(size_t pending_pkt_cap);

#ifdef __cplusplus
}
#endif
