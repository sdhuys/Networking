#include "icmp.h"
#include <stdio.h>

pkt_result send_icmp_down(struct nw_layer_t *self, struct pkt_t *packet)
{
	packet->offset -= sizeof(struct ipv4_header_t);
	packet->len += sizeof(struct ipv4_header_t);
	return self->downs[0]->send_down(self->downs[0], packet);
}

pkt_result receive_icmp_up(struct nw_layer_t *self, struct pkt_t *packet)
{
	struct icmp_header_t *header = (struct icmp_header_t *)(packet->data + packet->offset);
	struct checksum_chunk chunk =  {.data = header, .len = packet->len};
	if (calc_checksum(&chunk, 1) != 0)
		return ICMP_CHECKSUM_ERROR;

	switch (header->type) {
	case ECHO_REPLY:
		return ICMP_ECHO_REPLY_RCVD;
	case ECHO_REQUEST:
		memcpy(packet->dest_ip, packet->src_ip, IPV4_ADDR_LEN);
		echo_request_to_reply(packet, header);
		return send_icmp_down(self, packet);
	default:
		return ICMP_TYPE_NOT_SUPPORTED;
	}
}

void echo_request_to_reply(struct pkt_t *packet, struct icmp_header_t *header)
{
	memcpy(packet->dest_ip, packet->src_ip, IPV4_ADDR_LEN);
	packet->protocol = ICMP;
	header->type = 0;
	header->code = 0;
	header->checksum = 0;
	struct checksum_chunk chunk =  {.data = header, .len = packet->len};
	header->checksum = htons(calc_checksum(&chunk, 1));
}
