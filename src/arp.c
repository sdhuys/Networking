#include "arp.h"
#include "buffer_pool.h"
#include "constants.h"
#include "ethernet.h"
#include "nw_interface.h"
#include "nw_layer.h"
#include "pkt.h"
#include "routing_table.h"
#include <arpa/inet.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct arp_table *create_arp_table(struct nw_layer *arp, size_t pending_pkt_cap)
{
	assert(pending_pkt_cap <= ARP_NODE_PENDING_PKT_CAP);
	struct arp_table *table = malloc(sizeof(*table));
	if (!table)
		return NULL;

	struct arp_context *arp_cntx = (struct arp_context *)arp->context;

	table->head = NULL;
	table->arp_layer = arp;
	table->node_pending_pkt_cap = pending_pkt_cap;
	table->timer_mngr = arp_cntx->timer_mgr;
	if (pthread_mutex_init(&table->lock, NULL) != 0) {
		free(table);
		return NULL;
	}
	return table;
}

struct arp_table_node *create_arp_node(struct arp_table *table, size_t pending_pkt_cap)
{
	struct arp_table_node *node = calloc(1, sizeof(*node));
	if (!node)
		return NULL;
	node->pending_pkts = calloc(pending_pkt_cap, sizeof(struct pkt *));
	if (!node->pending_pkts) {
		free(node);
		return NULL;
	}
	node->table = table;
	node->pending_packets_count = 0;
	node->retries = 0;
	node->retry_timer = create_timer_owned(
	    arp_retry_callback, node, retain_arp_tbl_node_void, release_arp_tbl_node_void);
	if (!node->retry_timer) {
		free(node->pending_pkts);
		free(node);
		return NULL;
	}
	return node;
}

void destroy_arp_tbl_node(struct arp_table_node *n)
{
	for (int i = n->pending_packets_count; i > 0; i--) {
		release_pkt(n->pending_pkts[i - 1]);
	}
	free(n->pending_pkts);
	free(n->retry_timer);
	free(n);
}

void retain_arp_tbl_node_void(void *n)
{
	struct arp_table_node *node = (struct arp_table_node *)n;
	retain_arp_tbl_node(node);
}

void retain_arp_tbl_node(struct arp_table_node *n)
{
	atomic_fetch_add(&n->ref_count, 1);
}

void release_arp_tbl_node_void(void *n)
{
	struct arp_table_node *node = (struct arp_table_node *)n;
	release_arp_tbl_node(node);
}

void release_arp_tbl_node(struct arp_table_node *n)
{
	unsigned int prev = atomic_fetch_sub(&n->ref_count, 1);
	if (prev == 1)
		destroy_arp_tbl_node(n);
}

void arp_retry_callback(void *arg)
{
	struct arp_table_node *n = (struct arp_table_node *)arg;
	struct arp_table *table = n->table;

	pthread_mutex_lock(&n->table->lock);

	if (!timer_should_execute(table->timer_mngr, n->retry_timer)) {
		pthread_mutex_unlock(&n->table->lock);
		return;
	}

	if (n->retries >= ARP_MAX_RETRIES) {
		remove_arp_tbl_node(n);
		pthread_mutex_unlock(&n->table->lock);
		return;
	}
	n->retries++;
	start_timer(table->timer_mngr, n->retry_timer, ARP_RETRY_MS);
	pthread_mutex_unlock(&n->table->lock);

	struct pkt *p = create_arp_request_for(table->arp_layer, n->ipv4_addr, n->if_index);
	if (p) {
		send_arp_down(table->arp_layer, p);
		release_pkt(p);
	}
}

pkt_result receive_arp_up(struct nw_layer *self, struct pkt *packet)
{
	if (packet->len < sizeof(struct arp_data))
		return ARP_MALFORMED;

	struct arp_data *arp_data = (struct arp_data *)(packet->data + packet->offset);
	uint16_t hw_type = ntohs(arp_data->hw_type);

	// ONLY SUPPORTING ETHERNET
	if (hw_type != ETHERNET)
		return ARP_HW_TYPE_NOT_SUPPORTED;

	uint16_t proto_type = ntohs(arp_data->proto_type);
	// ONLY SUPPORTING IVP4
	if (proto_type != IPV4)
		return ARP_PRTCL_TYPE_NOT_SUPPORTED;

	uint16_t op = ntohs(arp_data->operation);
	unsigned char proto_addr_len = arp_data->prtcl_addr_len;
	unsigned char hw_addr_len = arp_data->hw_addr_len;
	if (proto_addr_len != IPV4_ADDR_LEN || hw_addr_len != MAC_ADDR_LEN)
		return ARP_MALFORMED;

	struct arp_context *cntx = (struct arp_context *)self->context;

	if (op == ARP_REQUEST) {
		struct nw_interface *interfaces = cntx->nw_ifs;
		uint32_t if_index = packet->if_index;
		ipv4_address_t local_ip_addr;
		memcpy(local_ip_addr, &interfaces[if_index].ipv4_addr, IPV4_ADDR_LEN);
		mac_address_t local_mac_addr;
		memcpy(local_mac_addr, &interfaces[if_index].mac_addr, MAC_ADDR_LEN);

		if (memcmp(arp_data->target_ip, local_ip_addr, proto_addr_len) != 0)
			return ARP_RQST_TARGET_NOT_RELEVANT;

		inc_arp_request_to_reply(packet, arp_data, local_mac_addr);
		pkt_result r = send_arp_down(self, packet);
		if (r == SENT)
			return ARP_REPLY_SENT;
		return r;
	}

	else if (op == ARP_REPLY) {
		pthread_mutex_lock(&cntx->arp_table->lock);
		struct arp_table_node *arp_entry =
		    query_arp_table(cntx->arp_table, arp_data->src_ip);

		// Unsolicited ARP responses dropped
		if (arp_entry == NULL || arp_entry->status == ARP_REACHABLE) {
			pthread_mutex_unlock(&cntx->arp_table->lock);
			return ARP_REPLY_NOT_RQSTD;
		}

		complete_arp_table_node(arp_entry, arp_data->src_mac);

		struct pkt *flushers[ARP_NODE_PENDING_PKT_CAP];
		size_t flush_count = arp_entry->pending_packets_count;
		memcpy(flushers, arp_entry->pending_pkts, flush_count * sizeof(flushers[0]));
		arp_entry->pending_packets_count = 0;
		mac_address_t mac;
		memcpy(&mac, &arp_entry->mac_addr, MAC_ADDR_LEN);
		pthread_mutex_unlock(&cntx->arp_table->lock);

		flush_q(self, flushers, flush_count, mac);
		return ARP_TABLE_UPDATED_Q_FLUSHED;
	}

	else
		return ARP_UNKNOWN_OPERATION;
}
// flush after unlocking, provide copies so arp nodes aren't touched after the unlock
void flush_q(struct nw_layer *self, struct pkt **pkts, size_t count, mac_address_t mac)
{
	struct nw_layer *eth = self->downs[0];
	for (size_t i = 0; i < count; i++) {
		struct pkt *p = pkts[i];
		memcpy(&p->dest_mac, mac, MAC_ADDR_LEN);
		eth->send_down(eth, p);
		release_pkt(p); // the queue's reference
	}
}

// caller holds table->lock
struct arp_table_node *insert_incomplete_for_ip(struct arp_table *table,
						ipv4_address_t dest_ip,
						size_t nw_if_indx)
{
	struct arp_table_node *node = create_arp_node(table, table->node_pending_pkt_cap);
	if (node == NULL)
		return NULL;
	node->if_index = nw_if_indx;
	memcpy(node->ipv4_addr, dest_ip, IPV4_ADDR_LEN);
	node->status = ARP_INCOMPLETE;
	node->last_updated = time(NULL);
	node->next = table->head;
	table->head = node;
	retain_arp_tbl_node(node);
	return node;
}

// caller holds table->lock
void remove_arp_tbl_node(struct arp_table_node *n)
{
	struct arp_table *table = n->table;
	struct arp_table_node *c = table->head;
	struct arp_table_node *prev = NULL;
	for (; c != NULL; c = c->next) {
		if (c == n) {
			if (prev)
				prev->next = n->next;
			else
				table->head = n->next;
			release_arp_tbl_node(n);
			return;
		}
		prev = c;
	}
}

// caller holds table->lock
pkt_result add_pkt_to_q(struct arp_table *table, struct arp_table_node *node, struct pkt *p)
{
	if (node->pending_packets_count == table->node_pending_pkt_cap)
		return ARP_TABLE_NODE_PKT_Q_FULL;
	retain_pkt(p);
	node->pending_pkts[node->pending_packets_count++] = p;
	return PACKET_QUEUED_AWAITING_ARP;
}

// caller holds table->lock
struct arp_table_node *query_arp_table(struct arp_table *table, ipv4_address_t ip)
{
	struct arp_table_node *node = table->head;
	for (; node != NULL; node = node->next)
		if (memcmp(ip, node->ipv4_addr, IPV4_ADDR_LEN) == 0)
			return node;

	return NULL;
}

// caller holds table->lock
void complete_arp_table_node(struct arp_table_node *entry, mac_address_t src_mac)
{
	memcpy(entry->mac_addr, src_mac, MAC_ADDR_LEN);
	entry->last_updated = time(NULL);
	entry->status = ARP_REACHABLE;
	entry->retries = 0;
	struct timer_manager *tm = entry->table->timer_mngr;
	cancel_timer(tm, entry->retry_timer);
}

void inc_arp_request_to_reply(struct pkt *packet,
			      struct arp_data *header,
			      mac_address_t requested_address)
{
	memcpy(packet->dest_mac, header->src_mac, header->hw_addr_len);

	header->operation = htons(ARP_REPLY);
	memcpy(header->target_mac, header->src_mac, header->hw_addr_len);
	memcpy(header->src_mac, requested_address, header->hw_addr_len);
	ipv4_address_t temp_ip;
	memcpy(temp_ip, header->target_ip, header->prtcl_addr_len);
	memcpy(header->target_ip, header->src_ip, header->prtcl_addr_len);
	memcpy(header->src_ip, temp_ip, header->prtcl_addr_len);
}

void print_arp_header(struct arp_data *arp_header)
{
	printf("ARP Header:\n");
	printf("  Hardware Type: %u\n", ntohs(arp_header->hw_type));
	printf("  Protocol Type: 0x%04x\n", ntohs(arp_header->proto_type));
	printf("  Hardware Address Length: %u\n", arp_header->hw_addr_len);
	printf("  Protocol Address Length: %u\n", arp_header->prtcl_addr_len);
	printf("  Operation: %u\n", ntohs(arp_header->operation));

	printf("  Sender MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
	       arp_header->src_mac[0],
	       arp_header->src_mac[1],
	       arp_header->src_mac[2],
	       arp_header->src_mac[3],
	       arp_header->src_mac[4],
	       arp_header->src_mac[5]);

	printf("  Sender IP: %u.%u.%u.%u\n",
	       arp_header->src_ip[0],
	       arp_header->src_ip[1],
	       arp_header->src_ip[2],
	       arp_header->src_ip[3]);

	printf("  Target MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
	       arp_header->target_mac[0],
	       arp_header->target_mac[1],
	       arp_header->target_mac[2],
	       arp_header->target_mac[3],
	       arp_header->target_mac[4],
	       arp_header->target_mac[5]);

	printf("  Target IP: %u.%u.%u.%u\n\n",
	       arp_header->target_ip[0],
	       arp_header->target_ip[1],
	       arp_header->target_ip[2],
	       arp_header->target_ip[3]);
}

// creates a new pkt ref, caller must release
struct pkt *create_arp_request_for(struct nw_layer *self, ipv4_address_t target_ip, size_t if_index)
{
	printf("CREATE ARP REQUEST ALLOCATING \n");
	struct pkt *pkt = allocate_pkt();
	if (pkt == NULL)
		return NULL;

	size_t eth_sz = sizeof(struct ethernet_header);
	size_t arp_sz = sizeof(struct arp_data);
	pkt->offset = eth_sz;
	pkt->len = eth_sz + arp_sz;
	pkt->if_index = if_index;

	memcpy(pkt->dest_mac, IPV4_BROADCAST_MAC, MAC_ADDR_LEN);

	struct arp_context *arp_context = (struct arp_context *)self->context;
	struct arp_data *arp = (struct arp_data *)(pkt->data + pkt->offset);

	arp->hw_type = htons(ETHERNET);
	arp->proto_type = htons(IPV4);
	arp->hw_addr_len = MAC_ADDR_LEN;
	arp->prtcl_addr_len = IPV4_ADDR_LEN;
	arp->operation = htons(ARP_REQUEST);

	struct nw_interface *interfaces = arp_context->nw_ifs;

	memcpy(arp->src_mac, &interfaces[if_index].mac_addr, MAC_ADDR_LEN);
	memcpy(arp->src_ip, &interfaces[if_index].ipv4_addr, IPV4_ADDR_LEN);
	memcpy(arp->target_ip, target_ip, IPV4_ADDR_LEN);
	memset(arp->target_mac, 0x00, MAC_ADDR_LEN);

	print_arp_header(arp);
	return pkt;
}

pkt_result send_arp_down(struct nw_layer *self, struct pkt *packet)
{
	// printf("SENDING ARP DOWN \n");
	// print_arp_header((struct arp_data_t *)&packet->data[packet->offset]);
	packet->ethertype = htons(ARP);
	packet->offset -= sizeof(struct ethernet_header);
	packet->len += sizeof(struct ethernet_header);
	pkt_result r = self->downs[0]->send_down(self->downs[0], packet);
	return r;
}