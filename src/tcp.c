#include "tcp.h"

pkt_result send_tcp_down(struct nw_layer *self, struct pkt *packet)
{
	struct tcp_header_no_options *header =
	    (struct tcp_header_no_options *)(packet->data + packet->offset);

	if (packet->tcp_options->length > 0) {
		unsigned char *opt_buff = (unsigned char *)(header) + sizeof(*header);
		tcp_serialize_options(opt_buff, packet->tcp_options->length, packet->tcp_options);
	}

	header->dest_port = htons(packet->dest_port);
	header->src_port = htons(packet->src_port);
	header->seq_num = htonl(packet->tcp_seq);
	header->ack_num = htonl(packet->tcp_ack);
	header->window = htons(packet->rcv_window);
	header->flags = packet->tcp_flags;
	header->data_offset = packet->tcp_data_offset;
	header->checksum = 0;
	header->checksum = htons(calc_tcp_checksum(packet));

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
	unsigned char *options_start =
	    packet->data + packet->offset + sizeof(struct tcp_header_no_options);
	struct tcp_options options;

	bool valid_options = parse_tcp_options(options_start, options_len, &options);
	if (!valid_options)
		return TCP_OPTIONS_MALFORMED;

	struct tcp_context *context = (struct tcp_context *)self->context;
	struct socket_manager *mgr = context->socket_manager;
	packet->dest_port = ntohs(header->dest_port);
	packet->src_port = ntohs(header->src_port);
	packet->offset += tcp_header_len;
	packet->len -= tcp_header_len;

	struct tcp_segment seg = {.header = header,
				  .options = &options,
				  .options_len = options_len,
				  .payload = packet->data + packet->offset,
				  .payload_len = packet->len};

	struct tcp_conn_id id = {.extern_port = packet->src_port, .loc_port = packet->dest_port};
	memcpy(id.extern_addr, packet->src_ip, IPV4_ADDR_LEN);
	memcpy(id.loc_addr, packet->dest_ip, IPV4_ADDR_LEN);
	// query established connections (also includes half-opens app started as client)
	struct tcp_ipv4_conn *conn = query_tcp_conn_hashtable(mgr->tcp_ipv4_conn_htable, id);

	// if not established, try time_wait connections
	if (conn == NULL) {
		conn = query_tcp_conn_hashtable(mgr->tcp_ipv4_conn_time_wait_htable, id);
	}
	if (conn != NULL) {
		pkt_result r = process_tcp_segment(&seg, conn);
		if (r == TCP_SEQ_OUT_OF_WNDW_RANGE_RST)
			tcp_fast_reply_rst(self, conn, packet, &seg);
		return r;
	}
	// if neither, find listener
	struct tcp_ipv4_listener *lstnr = query_tcp_listener_hashtable(
	    mgr->tcp_ipv4_listener_htable, packet->dest_port, packet->dest_ip);

	if (lstnr != NULL) {
		// find half-open connection
		conn = query_tcp_conn_hashtable(lstnr->half_opens, id);
		// only ACK's are relevant for half-open connections
		if (conn != NULL && header->flags & TCP_ACK) {
			return half_open_check_ack(&seg, conn, lstnr);
		}

		// NO TCP_CONNECTION_SOCKET OBJECT EXISTS YET:
		// if proper SYN without ACK, open new connection
		// can include ECE, CWR
		if ((header->flags & (TCP_SYN | TCP_ACK)) == TCP_SYN) {
			// syn cookie open
			if (lstnr->half_open_count >= lstnr->half_open_limit) {
				pkt_result r = tcp_fast_reply_syn_cookie(self, lstnr, packet, &seg);
				if (r == SENT)
					return TCP_SYN_COOKIE_SENT;
				return r;
			}
			// regular open
			return tcp_server_open_new_connection(lstnr, packet, &seg);
		}

		// if ACK, check for valid SYN cookie
		if (header->flags & TCP_ACK) {
			return syn_cookie_check_ack(lstnr, &seg, packet);
		}
	}

	// no connection, not a listener SYN
	if ((header->flags & TCP_RST) == 0) {
		tcp_fast_reply_rst(self, NULL, packet, &seg);
	}
	return TCP_NO_CONNECTION;
}

// fast SYN ACK reply bypassing send buffer
pkt_result tcp_fast_reply_syn_cookie(struct nw_layer *tcp,
				     struct tcp_ipv4_listener *listener,
				     struct pkt *packet,
				     struct tcp_segment *seg)
{
	packet->tcp_seq = generate_syn_cookie_iss(listener, seg, packet);
	uint32_t incoming_seq = ntohl(seg->header->seq_num);

	init_reply_packet_from_incoming(packet, seg);
	packet->tcp_flags = TCP_SYN | TCP_ACK;
	packet->tcp_ack = incoming_seq + seg_len(seg);
	packet->rcv_window = 65535;

	// options, MSS and SACK encoded in cookie, can safely negotiate
	packet->tcp_options->mss_present = seg->options->mss_present;
	if (seg->options->mss_present) {
		struct routing_table *table = ((struct tcp_context *)(tcp->context))->routing_tbl;
		struct route *route;
		if (!get_route(table, packet->src_ip, route))
			return TCP_UNROUTABLE_CONNECTION;

		packet->tcp_options->mss =
		    route->mtu - sizeof(struct ipv4_header) - sizeof(struct tcp_header_no_options);
	}
	packet->tcp_options->sack_permitted = seg->options->sack_permitted;

	packet->tcp_options->ts_present = false;
	packet->tcp_options->wscale_present = true;
	// FIGURE OUT BUFFER SIZE => ADVERTISE APPROPRIATE SCALE
	packet->tcp_options->wscale = 1;

	size_t options_len = tcp_options_length(packet->tcp_options);
	packet->tcp_data_offset = ((sizeof(*seg->header) + options_len) / 4) << 4;
	packet->len = sizeof(*seg->header) + options_len;
	packet->offset = MAX_ETH_FRAME_SIZE - packet->len;
	printf("SENDING SYN COOKIE DOWN \n");
	return tcp->send_down(tcp, packet);
}

// fast RST reply bypassing send buffer
pkt_result tcp_fast_reply_rst(struct nw_layer *tcp,
			      struct tcp_ipv4_conn *conn,
			      struct pkt *packet,
			      struct tcp_segment *seg)
{
	uint32_t incoming_seq = ntohl(seg->header->seq_num);
	uint32_t incoming_ack = ntohl(seg->header->ack_num);

	init_reply_packet_from_incoming(packet, seg);
	memset(packet->tcp_options, 0, sizeof(*packet->tcp_options));

	packet->tcp_data_offset = (sizeof(*seg->header) / 4) << 4;
	packet->len = sizeof(*seg->header);
	packet->offset = MAX_ETH_FRAME_SIZE - sizeof(*seg->header);

	if (seg->header->flags & TCP_ACK) {
		packet->tcp_flags = TCP_RST;
		packet->tcp_seq = incoming_ack;
		packet->tcp_ack = 0;
	} else {
		packet->tcp_flags = TCP_RST | TCP_ACK;
		packet->tcp_seq = 0;
		packet->tcp_ack = incoming_seq + seg_len(seg);
	}

	if (conn != NULL)
		destroy_tcp_conn(conn);

	return tcp->send_down(tcp, packet);
}

// recycle incoming packet for a quick reply (not going through global TX q)
void init_reply_packet_from_incoming(struct pkt *pkt, const struct tcp_segment *seg)
{
	pkt->dest_port = ntohs(seg->header->src_port);
	pkt->src_port = ntohs(seg->header->dest_port);

	ipv4_address_t tmp;
	memcpy(tmp, pkt->dest_ip, IPV4_ADDR_LEN);
	memcpy(pkt->dest_ip, pkt->src_ip, IPV4_ADDR_LEN);
	memcpy(pkt->src_ip, tmp, IPV4_ADDR_LEN);
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