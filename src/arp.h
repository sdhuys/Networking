#pragma once
#include "buffer_pool.h"
#include "types.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

pkt_result receive_arp_up(struct nw_layer_t *self, struct pkt_t *packet);
pkt_result send_arp_down(struct nw_layer_t *self, struct pkt_t *packet);
void print_arp_header(struct arp_data_t *arp_header);
void inc_arp_request_to_reply(struct pkt_t *packet,
			      struct arp_data_t *header,
			      mac_address requested_address);
void complete_arp_table_node(struct arp_table_node_t *entry, mac_address src_mac);
struct arp_table_node_t *query_arp_table(struct arp_table_t *table, ipv4_address ip);
struct pkt_t *create_arp_request_for(struct nw_layer_t *self, ipv4_address target_ip);
struct arp_table_node_t *insert_incomplete_for_ip(struct arp_table_t *table, ipv4_address dest_ip);
pkt_result add_pkt_to_q(struct arp_table_node_t *node, struct pkt_t *packet);
void flush_q(struct nw_layer_t *self, struct arp_table_node_t *arp_entry);

#ifdef __cplusplus
}
#endif
