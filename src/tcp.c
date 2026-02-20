#include "tcp.h"

pkt_result send_tcp_down(struct nw_layer *self, struct pkt *packet)
{
	struct tcp_header_no_options *header =
	    (struct tcp_header_no_options *)(packet->data + packet->offset);
	header->dest_port = htons(packet->dest_port);
	header->src_port = htons(packet->src_port);
	header->seq_num = htonl(packet->tcp_seq);
	header->ack_num = htonl(packet->tcp_ack);
	header->checksum = 0;
	header->checksum = calc_tcp_checksum(packet);
	header->flags = packet->tcp_flags;
	header->data_offset = packet->tcp_data_offset << 4;

	packet->offset -= sizeof(struct ipv4_header);
	packet->len += sizeof(struct ipv4_header);
	return self->downs[0]->send_down(self->downs[0], packet);
}

pkt_result receive_tcp_up(struct nw_layer *self, struct pkt *packet)
{
	if (packet->len < sizeof(struct tcp_header_no_options))
		return TCP_HEADER_MALFORMED;

	struct tcp_header_no_options *header =
	    (struct tcp_header_no_options *)(packet->data + packet->offset);

	size_t tcp_header_len = (header->data_offset >> 4) * 4; // in bytes
	if (tcp_header_len < 20 || tcp_header_len > packet->len)
		return TCP_HEADER_MALFORMED;

	if (bogus_flags_any(header->flags))
		return TCP_BOGUS_FLAGS;

	if (calc_tcp_checksum(packet) != 0)
		return TCP_CHECKSUM_ERROR;

	size_t options_len = tcp_header_len - sizeof(struct tcp_header_no_options);
	unsigned char *options =
	    (packet->data + packet->offset + sizeof(struct tcp_header_no_options));

	struct tcp_context *context = (struct tcp_context *)self->context;
	struct socket_manager *mgr = context->socket_manager;
	packet->dest_port = ntohs(header->dest_port);
	packet->src_port = ntohs(header->src_port);
	packet->offset += tcp_header_len;
	packet->len -= tcp_header_len;

	struct tcp_segment seg = {.header = header,
				  .options = options,
				  .options_len = options_len,
				  .payload = packet->data + packet->offset,
				  .payload_len = packet->len};

	struct tcp_conn_id id = {.extern_port = packet->src_port, .loc_port = packet->dest_port};
	memcpy(id.extern_addr, packet->src_ip, IPV4_ADDR_LEN);
	memcpy(id.loc_addr, packet->src_ip, IPV4_ADDR_LEN);
	// query established connections
	struct tcp_ipv4_conn *conn = query_tcp_conn_hashtable(mgr->tcp_ipv4_conn_htable, id);
	printf("YELOOOOOOOOOOOOOO1 %d\n\n", mgr->tcp_ipv4_conn_htable == NULL);

	// if not established, try time_wait connections
	if (conn == NULL) {
		conn = query_tcp_conn_hashtable(mgr->tcp_ipv4_conn_time_wait_htable, id);
		printf("YELOOOOOOOOOOOOOO2\n\n");
	}
	if (conn != NULL) {
		pkt_result r = process_tcp_segment(seg, conn);
		if (r == TCP_SEQ_OUT_OF_WNDW_RANGE_RST)
			tcp_reply_rst(self, conn, packet, header);
		return r;
	}

	// if neither, find listener
	struct tcp_ipv4_listener *lstnr = query_tcp_listener_hashtable(
	    mgr->tcp_ipv4_listener_htable, packet->dest_port, packet->dest_ip);
	if (lstnr != NULL) {
		// find half-open connection
		conn = query_tcp_conn_hashtable(lstnr->half_opens, id);
		if (conn != NULL) {
			return process_tcp_segment_half_open(seg, conn, lstnr);
		}

		// if proper SYN without ACK, open new connection
		if ((header->flags & TCP_SYN) != 0 && (header->flags & TCP_ACK) == 0) {
			return process_incoming_syn(lstnr, seg);
		}
	}
	printf("FLAGS: %d \n\n", header->flags & TCP_RST);

	// no connection, not a listener SYN
	if ((header->flags & TCP_RST) == 0) {
		tcp_reply_rst(self, NULL, packet, header);
	}
	return TCP_NO_CONNECTION;
}

pkt_result tcp_reply_rst(struct nw_layer *tcp,
			 struct tcp_ipv4_conn *conn,
			 struct pkt *packet,
			 struct tcp_header_no_options *header)
{
	uint32_t incoming_seq = ntohl(header->seq_num);
	uint32_t incoming_ack = ntohl(header->ack_num);
	packet->dest_port = ntohs(header->src_port);
	packet->src_port = ntohs(header->dest_port);

	ipv4_address t;
	memcpy(t, packet->dest_ip, IPV4_ADDR_LEN);
	memcpy(packet->dest_ip, packet->src_ip, IPV4_ADDR_LEN);
	memcpy(packet->src_ip, t, IPV4_ADDR_LEN);

	packet->tcp_data_offset = sizeof(*header) / 4;

	if (header->flags & TCP_ACK) {
		packet->tcp_flags = TCP_RST;
		packet->tcp_seq = incoming_ack;
		packet->tcp_ack = 0;
	} else {
		uint32_t seglen = packet->len;
		if (header->flags & TCP_SYN)
			seglen++;
		if (header->flags & TCP_FIN)
			seglen++;

		packet->tcp_flags = TCP_RST | TCP_ACK;
		packet->tcp_seq = 0;
		packet->tcp_ack = incoming_seq + seglen;
	}

	if (conn != NULL)
		destroy_tcp_conn(conn);

	packet->len = sizeof(*header);
	packet->offset = MAX_ETH_FRAME_SIZE - sizeof(*header);

	return tcp->send_down(tcp, packet);
}

// nonsonsical combinations regardsless of listener or connection state
bool bogus_flags_any(uint16_t flags)
{
	if (flags == 0)
		return true;

	if ((flags & TCP_SYN) == 0)
		return false;
	if ((flags & TCP_FIN) != 0)
		return true;
	if ((flags & TCP_RST) != 0)
		return true;
	return false;
}

// assuming:
// - packet->len is tcp header + payload length
// - packet->data + packet->offset is tcp header start
uint16_t calc_tcp_checksum(struct pkt *packet)
{
	struct ipv4_pseudo_header pseudo_h = {
	    .len = htons(packet->len), .padding = 0, .protocol = P_TCP};
	memcpy(pseudo_h.dest_ip, packet->dest_ip, IPV4_ADDR_LEN);
	memcpy(pseudo_h.src_ip, packet->src_ip, IPV4_ADDR_LEN);

	struct checksum_chunk chunks[2] = {
	    {.data = &pseudo_h, .len = sizeof(pseudo_h)},
	    {.data = packet->data + packet->offset, .len = packet->len}};

	return calc_checksum(chunks, 2);
}