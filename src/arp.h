#pragma once
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include "buffer_pool.h"
#include "types.h"

pkt_result receive_arp_up(struct nw_layer *self, struct pkt *packet);
pkt_result send_arp_down(struct nw_layer *self, struct pkt *packet);
void print_arp_header(struct arp_data *arp_header);
void inc_arp_request_to_reply(struct pkt *packet, struct arp_data *header,
                              mac_address requested_address);
void complete_arp_table_node(struct arp_table_node *entry, mac_address src_mac);
struct arp_table_node *query_arp_table(struct arp_table *table,
                                       ipv4_address ip);
struct pkt *create_arp_request_for(struct nw_layer *self,
                                   ipv4_address target_ip);
struct arp_table_node *insert_incomplete_for_ip(struct arp_table *table,
                                                ipv4_address dest_ip);
pkt_result add_pkt_to_q(struct arp_table_node *node, struct pkt *packet);
void flush_q(struct nw_layer *self, struct arp_table_node *arp_entry);