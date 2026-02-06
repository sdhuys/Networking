#include "udp.h"
#include <execinfo.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

pkt_result send_udp_down(struct nw_layer_t *self, struct pkt_t *packet)
{
	packet->len += sizeof(struct udp_header_t);

	struct udp_header_t *header = (struct udp_header_t *)(packet->data + packet->offset);
	header->dest_port = htons(packet->dest_port);
	header->src_port = htons(packet->src_port);
	header->length = htons(packet->len);
	header->checksum = 0;
	header->checksum = compute_checksum_internal(header, packet);

	packet->offset -= sizeof(struct ipv4_header_t);
	packet->len += sizeof(struct ipv4_header_t);

	return self->downs[0]->send_down(self->downs[0], packet);
}

pkt_result receive_udp_up(struct nw_layer_t *self, struct pkt_t *packet)
{
	struct udp_header_t *header = (struct udp_header_t *)(packet->data + packet->offset);

	if (header->checksum != 0)
		if (compute_checksum_internal(header, packet) != 0)
			return UDP_CHECKSUM_ERROR;

	struct udp_context_t *context = (struct udp_context_t *)self->context;
	packet->dest_port = ntohs(header->dest_port);
	packet->src_port = ntohs(header->src_port);
	struct udp_ipv4_socket_t *socket =
	    query_hashtable(context->sock_manager->udp_ipv4_sckt_htable, packet->dest_port);

	if (socket == NULL)
		return UDP_PORT_NO_LISTENER;

	packet->offset += sizeof(struct udp_header_t);
	packet->len -= sizeof(struct udp_header_t);

	pkt_result r = write_up_to_rcv_buffer(socket, packet);
	release_udp_socket(socket);
	return r;
}

uint16_t compute_checksum_internal(struct udp_header_t *header, struct pkt_t *packet)
{
	struct ipv4_pseudo_header_t pseudo_h = {
	    .len = header->length, // Already in network byte order
	    .padding = 0,
	    .protocol = P_UDP,
	};
	memcpy(pseudo_h.dest_ip, packet->dest_ip, IPV4_ADDR_LEN);
	memcpy(pseudo_h.src_ip, packet->src_ip, IPV4_ADDR_LEN);

	struct checksum_chunk chunks[2] = {
	    {.data = &pseudo_h, .len = sizeof(struct ipv4_pseudo_header_t)},
	    {.data = (uint8_t *)packet->data + packet->offset, .len = packet->len}};

	return calc_checksum(chunks, 2);
}