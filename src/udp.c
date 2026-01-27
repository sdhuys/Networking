#include "udp.h"

pkt_result send_udp_down(struct nw_layer_t *self, struct pkt_t *packet)
{
	return NOT_IMPLEMENTED_YET;
}

pkt_result receive_udp_up(struct nw_layer_t *self, struct pkt_t *packet)
{
	if (!validate_checksum)
		return UDP_CHECKSUM_ERROR;
	struct udp_header_t *header = (struct udp_header_t *)packet->data[packet->offset];
	return 123456;
}

bool validate_checksum(struct udp_header_t *header, struct pkt_t *packet)
{
	// no checksum used
	if (header->checksum == 0)
		return true;

	struct ipv4_pseudo_header_t *ps_ip_h = (struct ipv4_pseudo_header_t *)&packet->src_ip;
	struct checksum_chunk chunks[2] = {
	    {.data = packet->data + packet->offset, .len = packet->len},
	    {.data = ps_ip_h, .len = sizeof(struct ipv4_pseudo_header_t)}};
	return calc_checksum(chunks, 2) == 0;
}