#include "syn_cookie.h"
#include "tcp.h"
#include "tcp_listener_socket.h"

#define COOKIE_MSS_VAL_COUNT 4

static const uint16_t mss_enc_table[] = {TCP_MSS_DEFAULT_FALLBACK, 1300, 1440, TCP_MSS_MAX};
uint8_t mss_encode(uint16_t mss);
uint16_t mss_decode(uint8_t enc);

uint32_t generate_syn_cookie_iss(struct tcp_ipv4_listener *listener,
				 struct tcp_segment *seg,
				 struct pkt *p)
{
	uint32_t mss = seg->options->mss_present ? seg->options->mss : TCP_MSS_DEFAULT_FALLBACK;
	mss = mss_encode(mss);
	uint8_t mss_sack = (mss << 1) | seg->options->sack_permitted;

	// time in 64 seconds resolution
	uint64_t time = now_s() >> 6;
	uint32_t hash = hash_syncookie(
	    listener->local_addr, p->src_ip, listener->local_port, seg->header->src_port, time);
	// encoded in 5 bits
	time &= 0x1F;

	uint32_t iss = time;
	iss = (iss << 3) | mss_sack;
	iss = (iss << 24) | hash;
	return iss;
}

uint8_t mss_encode(uint16_t mss)
{
	for (int i = COOKIE_MSS_VAL_COUNT - 1; i >= 0; i--) {
		if (mss >= mss_enc_table[i])
			return i;
	}
	return 0;
}

uint16_t mss_decode(uint8_t enc)
{
	if (enc >= COOKIE_MSS_VAL_COUNT)
		enc = COOKIE_MSS_VAL_COUNT - 1;
	return mss_enc_table[enc];
}

pkt_result syn_cookie_check_ack(struct tcp_ipv4_listener *listener,
				struct tcp_segment *seg,
				struct pkt *p)
{
	uint32_t cookie = ntohl(seg->header->ack_num) - 1;
	// top 5 bits: t
	// middle 3 bits: 2 bits encoded MSS, 1 bit sack_permitted
	// bottom 24 bits: hash
	uint32_t received_t_bits = (cookie >> 27);
	uint32_t received_mss_idx_sack = (cookie >> 24) & 7;
	uint32_t received_hash = cookie & 0x00FFFFFF;

	// current time in 64-second resolution.
	uint64_t now_t_full = now_s() >> 6;
	// 5 bit encoding
	uint8_t now_t_bits = (uint8_t)(now_t_full & 0x1F);

	// how many 64-second blocks have passed since the cookie was sent
	// due to wraparound delta 1 could mean any multiple of 32 * 64 seconds have passed
	// no way to filter out accidental very old connections (should be rare)
	uint8_t delta_t = (now_t_bits - received_t_bits) & 0x1F;

	// allow a window of 128 seconds (+ rare wraparound windows)
	if (delta_t >= 3)
		return TCP_SYN_COOKIE_EXPIRED;

	// reconstruct the original full timestamp used during generation.
	uint64_t original_t_full = now_t_full - delta_t;

	uint32_t expected_hash = hash_syncookie(listener->local_addr,
						p->src_ip,
						listener->local_port,
						seg->header->src_port,
						original_t_full);

	if (received_hash != expected_hash)
		return TCP_SYN_COOKIE_INVALID;

	uint32_t mss = mss_decode(received_mss_idx_sack >> 1);
	bool sack_permitted = received_mss_idx_sack & 1;

	struct tcp_conn_id id = {.loc_port = listener->local_port,
				 .extern_port = seg->header->src_port};
	memcpy(id.extern_addr, p->src_ip, IPV4_ADDR_LEN);
	memcpy(id.loc_addr, listener->local_addr, IPV4_ADDR_LEN);

	struct tcp_ipv4_conn *conn = create_init_tcp_connection(&id, listener->tcp_layer);
	if (!conn)
		return SYN_COOKIE_OUT_OF_MEMORY;

	// negotiated options
	conn->sack_enabled = sack_permitted;
	conn->snd_mss = mss;

	// lost options/features
	conn->ece_enabled = 0;
	conn->ts_enabled = false;
	conn->rcv_buffer->rcv_wscale = 0;
	conn->snd_buffer->snd_wscale = 0;

	struct tcp_context *cntx = (struct tcp_context *)(listener->tcp_layer->context);
	struct routing_table *table = cntx->routing_tbl;

	if (get_route(table, conn->extern_addr, &conn->route)) {
		conn->rcv_mss = conn->route->mtu - sizeof(struct ipv4_header) -
				sizeof(struct tcp_header_no_options);
	} else {
		conn->rcv_mss = TCP_MSS_DEFAULT_FALLBACK;
	}

	conn->snd_buffer->cwnd = TCP_INIT_CWND_MSS_MULT * conn->snd_mss;

	conn->iss = cookie;
	conn->irs = ntohl(seg->header->seq_num) - 1; // -1 to account for original SYN
	conn->rcv_buffer->rcv_nxt = conn->irs + seg_seq_len(seg);
	conn->snd_buffer->snd_nxt = cookie + 1;
	conn->snd_buffer->snd_una = cookie + 1;

	conn->state = ESTABLISHED;

	add_to_tcp_conn_hashtable(cntx->socket_manager->tcp_ipv4_conn_htable, conn);
	push_q(listener->ready_q, &conn->q_node, true);
	return SYN_COOKIE_CONN_CREATED;
}