#include "udp.h"

pkt_result send_udp_down(struct nw_layer_t *self, struct pkt_t *packet)
{
	packet->offset -= sizeof(struct ipv4_header_t);
	packet->len += sizeof(struct ipv4_header_t);
	// CREATE HEADER
	return self->send_down(self->downs[0], packet);
}

pkt_result receive_udp_up(struct nw_layer_t *self, struct pkt_t *packet)
{
	struct udp_header_t *header = (struct udp_header_t *)(packet->data + packet->offset);
	if (!validate_checksum(header, packet))
		return UDP_CHECKSUM_ERROR;

	packet->offset += sizeof(struct udp_header_t);
	packet->len -= sizeof(struct udp_header_t);

	struct udp_context_t *context = (struct udp_context_t *)self->context;
	uint16_t dest_port = ntohs(header->dest_port);
	struct udp_ipv4_socket_t *socket =
	    query_hashtable(context->sock_manager->udp_ipv4_sckt_htable, dest_port);
	if (socket == NULL)
		return UDP_PORT_NO_LISTENER;

	// LOCK SOCKET //
	pkt_result r = write_up_to_rcv_buffer(context->sock_manager, socket, packet);
	release_udp_socket(socket);
	// UNLOCK SOCKET //

	return r;
}

bool validate_checksum(struct udp_header_t *header, struct pkt_t *packet)
{
	// no checksum used
	if (header->checksum == 0)
		return true;

	struct ipv4_pseudo_header_t pseudo_h = {
	    .len = header->length,
	    .padding = 0,
	    .protocol = P_UDP,
	};
	memcpy(pseudo_h.dest_ip, packet->dest_ip, IPV4_ADDR_LEN);
	memcpy(pseudo_h.src_ip, packet->src_ip, IPV4_ADDR_LEN);

	struct checksum_chunk chunks[2] = {
	    {.data = packet->data + packet->offset, .len = packet->len},
	    {.data = &pseudo_h, .len = sizeof(struct ipv4_pseudo_header_t)}};
	uint16_t checksum = calc_checksum(chunks, 2);
	return checksum == 0;
}