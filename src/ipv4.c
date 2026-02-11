#include "ipv4.h"
#include <stdio.h>

pkt_result receive_ipv4_up(struct nw_layer_t *self, struct pkt_t *packet)
{
	struct ipv4_header_t *header = (struct ipv4_header_t *)(packet->data + packet->offset);

	if (header->version_ihl >> 4 != IPV4_V)
		return IP_VERSION_MISMATCH;

	size_t header_len = (header->version_ihl & 0x0F);
	if (header_len != IPV4_HEADER_NO_OPTIONS_LEN)
		return IP_OPTIONS_NOT_SUPPORTED;

	// dscp_ecn ignored

	uint16_t flags_fragment_offset = ntohs(header->flags_fragment_offset);
	bool more_fragments = (flags_fragment_offset >> 13) & 0x1;
	uint16_t offset = flags_fragment_offset & 0x1FFF;
	if (more_fragments || (offset != 0))
		return IP_FRAGMENTATION_NOT_SUPPORTED;

	if (calc_ipv4_checksum(header, header_len) != 0)
		return IP_CHECKSUM_ERROR;

	if (!relevant_destination_ip(header->dest_ip, self))
		return IP_DEST_NOT_RELEVANT;

	memcpy(packet->src_ip, header->src_ip, IPV4_ADDR_LEN);
	memcpy(packet->dest_ip, header->dest_ip, IPV4_ADDR_LEN);
	packet->offset += header_len * 4; // == sizeof(struct ipv4_header) since we
					  // enforece NO OPTIONS in header
	packet->len -= header_len * 4;
	packet->protocol = header->protocol;
	switch (header->protocol) {
	case P_ICMP:
		return pass_up_to_layer(self, ICMP_NAME, packet);
	case P_TCP:
		return pass_up_to_layer(self, TCP_NAME, packet);
	case P_UDP:
		return pass_up_to_layer(self, UDP_NAME, packet);
	default:
		return IP_HDR_TRANSPORT_PROT_NOT_SUPPORTED;
	};
}

pkt_result send_ipv4_down(struct nw_layer_t *self, struct pkt_t *packet)
{
	packet->ethertype = htons(IPV4);

	struct ipv4_context_t *ipv4_cntxt = (struct ipv4_context_t *)self->context;
	struct nw_layer_t *arp_layer = ipv4_cntxt->arp_layer;
	struct arp_context_t *arp_cntxt = arp_layer->context;
	struct arp_table_t *arp_tbl = arp_cntxt->arp_table;

	// Find route
	struct route_t *next_hop_route = NULL;
	get_route(self, packet->dest_ip, &next_hop_route);

	if (next_hop_route == NULL)
		return IP_NO_ROUTE_FOUND; // should relay ICMP Destination Unreachable to UDP or TCP
	packet->if_index = next_hop_route->iface_id;

	// Write header
	struct ipv4_header_t *header = (struct ipv4_header_t *)(packet->data + packet->offset);
	write_ipv4_header(ipv4_cntxt, header, packet);

	// Prepare offset/length for lower layer (HAS TO HAPPEN BEFORE QUEUING!)
	packet->offset -= sizeof(struct ethernet_header_t);
	packet->len += sizeof(struct ethernet_header_t);

	// Prepare MAC metadata for lower layer
	unsigned char *next_hop = (next_hop_route->type == ROUTE_VIA)
				      ? (unsigned char *)&next_hop_route->gateway
				      : packet->dest_ip;

	struct arp_table_node_t *dest_ip_node = query_arp_table(arp_tbl, next_hop);

	if (dest_ip_node == NULL) {
		dest_ip_node = insert_incomplete_for_ip(arp_tbl, next_hop);
		struct pkt_t *arp_request = create_arp_request_for(arp_layer, next_hop);
		send_arp_down(arp_layer, arp_request);
	}
	if (dest_ip_node->status == ARP_INCOMPLETE) {
		printf("IPV4 ARP Q RETAINING \n");
		retain_pkt(packet);
		return add_pkt_to_q(dest_ip_node, packet);
	}
	memcpy(packet->dest_mac, dest_ip_node->mac_addr, MAC_ADDR_LEN);
	return self->downs[0]->send_down(self->downs[0], packet);
}

void write_ipv4_header(struct ipv4_context_t *context,
		       struct ipv4_header_t *header,
		       struct pkt_t *packet)
{
	header->version_ihl = (IPV4_V << 4) + IPV4_HEADER_NO_OPTIONS_LEN;
	header->dscp_ecn = 0; // could be set by metadata provided by application socket call
	header->total_length = htons(packet->len);
	header->id = 0; // can be 0 since we don't allow fragmentation
	header->flags_fragment_offset = htons(1 << 14); // DO NOT FRAGMENT
	header->ttl = IPV4_TTL_DEFAULT;
	header->protocol = packet->protocol;
	header->header_checksum = 0;
	header->header_checksum = calc_ipv4_checksum(header, IPV4_HEADER_NO_OPTIONS_LEN);
	// Because we're using a TAP device, we set source as stack's ip instead of interface's
	// ip
	// otherwise the stack never receives any replies
	memcpy(header->src_ip, context->stack_ipv4_addr, IPV4_ADDR_LEN);
	memcpy(header->dest_ip, packet->dest_ip, IPV4_ADDR_LEN);
}

bool relevant_destination_ip(ipv4_address dest_ip, struct nw_layer_t *self)
{
	struct ipv4_context_t *context = (struct ipv4_context_t *)self->context;

	if (memcmp(dest_ip, IPV4_BROADCAST_IP, IPV4_ADDR_LEN) == 0 ||
	    memcmp(dest_ip, context->stack_ipv4_addr, IPV4_ADDR_LEN) == 0)
		return true;
	return false;
}

void get_route(struct nw_layer_t *self, ipv4_address dest_ip, struct route_t **route_out)
{
	struct ipv4_context_t *context = (struct ipv4_context_t *)self->context;
	struct route_t *routes = context->routing_table;

	int longest_prefix = -1;

	uint32_t int_ip;
	memcpy(&int_ip, dest_ip, IPV4_ADDR_LEN);

	for (size_t i = 0; i < context->routes_amount; i++) {
		struct route_t *route = &routes[i];

		if (route->prefix_len > longest_prefix &&
		    ((int_ip & route->subnet_mask)) == route->prefix) {
			longest_prefix = route->prefix_len;
			*route_out = route;
		}
	}
}
