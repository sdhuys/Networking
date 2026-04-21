#include "icmp.h"
#include "checksum.h"
#include "ipv4.h"
#include "layer_router.h"
#include "nw_layer.h"
#include "pkt.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

pkt_result send_icmp_down(struct nw_layer *self, struct pkt *packet)
{
	packet->offset -= sizeof(struct ipv4_header);
	packet->len += sizeof(struct ipv4_header);
	return self->downs[0]->send_down(self->downs[0], packet);
}

pkt_result receive_icmp_up(struct nw_layer *self, struct pkt *packet)
{
	struct icmp_header *header = (struct icmp_header *)(packet->data + packet->offset);
	struct checksum_chunk chunk = {.data = header, .len = packet->len};

	uint16_t checksum = calc_checksum(&chunk, 1);

	// allow 0 instead of 0xFFFF
	if (!(checksum == 0xFFFF && header->checksum == 0) && calc_checksum(&chunk, 1) != 0)
		return ICMP_CHECKSUM_ERROR;

	switch (header->type) {
	case ECHO_REPLY:
		return ICMP_ECHO_REPLY_RCVD;
	case ECHO_REQUEST:
		echo_request_to_reply(packet, header);
		return send_icmp_down(self, packet);
	default:
		return ICMP_TYPE_NOT_SUPPORTED;
	}
}

void echo_request_to_reply(struct pkt *packet, struct icmp_header *header)
{
	ipv4_address_t temp;
	memcpy(temp, packet->dest_ip, IPV4_ADDR_LEN);
	memcpy(packet->dest_ip, packet->src_ip, IPV4_ADDR_LEN);
	memcpy(packet->src_ip, temp, IPV4_ADDR_LEN);
	packet->protocol = P_ICMP;
	header->type = 0;
	header->code = 0;
	header->checksum = 0;
	struct checksum_chunk chunk = {.data = header, .len = packet->len};
	header->checksum = htons(calc_checksum(&chunk, 1));
}
