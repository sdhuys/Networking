#include "ethernet.h"

pkt_result receive_frame_up(struct nw_layer_t *self, struct pkt_t *packet)
{
	struct ethernet_header_t *header = (struct ethernet_header_t *)packet->data;
	// print_incoming(header);

	if (relevant_destination_mac(header->dest_mac, self) == false) {
		// printf("Frame not relevant for us. Ignoring.\n");
		return FRAME_TARGET_NOT_RELEVANT;
	}

	packet->offset += sizeof(struct ethernet_header_t);
	packet->len -= sizeof(struct ethernet_header_t);

	unsigned short ethertype = ntohs(header->ethertype);
	switch (ethertype) {
	case IPV4:
		// printf("This is an IPv4 packet.\n");
		return pass_up_to_layer(self, IPV4_NAME, packet);
		break;
	case ARP:
		// printf("This is an ARP packet.\n");
		return pass_up_to_layer(self, ARP_NAME, packet);
		break;
	case IPV6:
		return ETHERTYPE_NOT_SUPPORTED;
		// printf("This is an IPv6 packet. Not supported yet\n");
		break;
	case VLAN:
		return ETHERTYPE_NOT_SUPPORTED;
		// printf("This is a VLAN tagged packet. Not supported yet\n");
		break;
	default:
		// printf("Unknown Ethertype: 0x%04x\n", ethertype);
		return ETHERTYPE_NOT_SUPPORTED;
		break;
	}
}

pkt_result send_frame_down(struct nw_layer_t *self, struct pkt_t *packet)
{
	struct ethernet_header_t *header =
	    (struct ethernet_header_t *)(packet->data + packet->offset);
	struct ethernet_context_t *context = (struct ethernet_context_t *)self->context;

	header->ethertype = packet->ethertype;
	memcpy(header->dest_mac, packet->dest_mac, MAC_ADDR_LEN);
	memcpy(header->src_mac, context->mac_addr, MAC_ADDR_LEN);

	return self->downs[0]->send_down(self->downs[0], packet);
}

// Only procees frames sent to stack's MAC or ipv4 broadcast
// No ipv6 mulicast support yet
bool relevant_destination_mac(mac_address dest_mac, struct nw_layer_t *self)
{
	struct ethernet_context_t *context = (struct ethernet_context_t *)self->context;

	if (memcmp(dest_mac, IPV4_BROADCAST_MAC, MAC_ADDR_LEN) == 0 ||
	    memcmp(dest_mac, context->mac_addr, MAC_ADDR_LEN) == 0)
		return true;
	return false;
}

void print_incoming(struct ethernet_header_t *header)
{
	printf("Incoming Ethernet Frame:\n");
	printf("Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
	       header->src_mac[0],
	       header->src_mac[1],
	       header->src_mac[2],
	       header->src_mac[3],
	       header->src_mac[4],
	       header->src_mac[5]);
	printf("Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
	       header->dest_mac[0],
	       header->dest_mac[1],
	       header->dest_mac[2],
	       header->dest_mac[3],
	       header->dest_mac[4],
	       header->dest_mac[5]);
	printf("Ethertype: 0x%04x\n", ntohs(header->ethertype));
}