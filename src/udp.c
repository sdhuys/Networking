#include "udp.h"
#include <assert.h>
#include <execinfo.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

pkt_result send_udp_down(struct nw_layer *self, struct pkt *packet)
{
	packet->len += sizeof(struct udp_header);

	struct udp_header *header = (struct udp_header *)(packet->data + packet->offset);
	header->dest_port = htons(packet->dest_port);
	header->src_port = htons(packet->src_port);
	header->length = htons(packet->len);
	header->checksum = 0;
	header->checksum = compute_checksum_internal(header, packet);

	packet->offset -= sizeof(struct ipv4_header);
	packet->len += sizeof(struct ipv4_header);

	return self->downs[0]->send_down(self->downs[0], packet);
}

pkt_result receive_udp_up(struct nw_layer *self, struct pkt *packet)
{
	struct udp_header *header = (struct udp_header *)(packet->data + packet->offset);

	if (ntohs(header->length) != packet->len)
		return UDP_MALFORMED;

	if (header->checksum != 0)
		if (compute_checksum_internal(header, packet) != 0)
			return UDP_CHECKSUM_ERROR;

	struct udp_context *context = (struct udp_context *)self->context;
	packet->dest_port = ntohs(header->dest_port);
	packet->src_port = ntohs(header->src_port);
	struct udp_ipv4_socket *socket = query_udp_hashtable(
	    context->sock_manager->udp_ipv4_sckt_htable, packet->dest_port, packet->dest_ip);

	if (socket == NULL)
		return UDP_PORT_NO_LISTENER;

	packet->offset += sizeof(struct udp_header);
	packet->len -= sizeof(struct udp_header);
	printf("RECEIVE UDP UP RETAINING \n");
	retain_pkt(packet);
	pkt_result r = write_up_to_rcv_buffer(socket, packet);
	release_udp_socket(socket);
	return r;
}

uint16_t compute_checksum_internal(struct udp_header *header, struct pkt *packet)
{
	struct ipv4_pseudo_header pseudo_h = {
	    .len = header->length, // Already in network byte order
	    .padding = 0,
	    .protocol = P_UDP,
	};
	memcpy(pseudo_h.dest_ip, packet->dest_ip, IPV4_ADDR_LEN);
	memcpy(pseudo_h.src_ip, packet->src_ip, IPV4_ADDR_LEN);

	struct checksum_chunk chunks[2] = {
	    {.data = &pseudo_h, .len = sizeof(struct ipv4_pseudo_header)},
	    {.data = (uint8_t *)packet->data + packet->offset, .len = packet->len}};

	return calc_checksum(chunks, 2);
}