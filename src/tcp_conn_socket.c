#include "tcp_conn_socket.h"
#include "tcp.h"

const struct socket_ops tcp_conn_ops = {.is_snd_queued = NULL,
					.set_snd_queued = NULL,
					.retain = tcp_retain_conn,
					.release = tcp_release_conn,
					.write_to_snd_buffer = NULL,
					.read_rcv_buffer = NULL,
					.unlock = tcp_unlock_conn,
					.lock = tcp_lock_conn,
					.snd_ready = NULL,
					.send_pkt = NULL,
					.close = NULL};

pkt_result process_tcp_segment(struct pkt *p, struct tcp_segment *seg, struct tcp_ipv4_conn *conn)
{
	uint32_t seq = ntohl(seg->header->seq_num);
	if (seg->header->flags & TCP_RST) {
		remove_from_tcp_conn_hashtable(conn->htable, conn);
		tcp_transition_to_state(conn, CLOSED);
		// notify threads waiting to read/write to cancel
		pthread_cond_broadcast(&conn->snd_buffer->cond);
		pthread_cond_broadcast(&conn->rcv_buffer->cond);
		return INC_RST_CONN_DEAD;
	}

	uint32_t rcv_next = conn->rcv_buffer->rcv_nxt;
	uint16_t rcv_wnd = conn->rcv_buffer->rcv_wnd;

	uint32_t seg_end = seq + seg->payload_len;
	if (tcp_seq_before_eq(seg_end, rcv_next))
		return TCP_SEG_DUPLICATE;

	if (tcp_seq_after(seq, rcv_next + rcv_wnd))
		return TCP_SEG_OUT_OF_WNDW_RANGE;

	// data handling (ESTABLISHED and payload present): delegate to rcv buffer helper
	if (conn->state == ESTABLISHED && seg->payload_len > 0) {
		rcv_buffer_write_tcp_segment(conn->rcv_buffer, seg);
	}
	return NOT_IMPLEMENTED_YET;
}

// enqueues the tcp connection sock to TX worker queue
// after dequeing actual ops.send_packet will check state and append ACK if needed
void tcp_syn_to_snd_buff(struct tcp_ipv4_conn *conn)
{
	sndbuf_insert_ghost_byte(conn->snd_buffer, TCP_SYN);
	struct socket_manager *mgr =
	    ((struct tcp_context *)conn->tcp_layer->context)->socket_manager;
	notify_socket_readable_snd(mgr, conn, &tcp_conn_ops);
}

uint32_t generate_random_iss()
{
	uint32_t x;
	if (getrandom(&x, sizeof(x), 0) != sizeof(x))
		abort();
	return x;
}

// create connection for id, init general values
struct tcp_ipv4_conn *create_init_tcp_connection(struct tcp_conn_id *id, struct nw_layer *tcp)
{
	struct tcp_ipv4_conn *conn = malloc(sizeof(*conn));
	if (!conn)
		return NULL;
	if (pthread_mutex_init(&conn->lock, NULL) < 0)
		return NULL;

	conn->snd_buffer = create_byte_snd_buffer(TCP_DEFAULT_BUFFER_SIZE);
	if (!conn->snd_buffer) {
		free(conn);
		return NULL;
	}

	conn->rcv_buffer = create_byte_rcv_buffer(TCP_DEFAULT_BUFFER_SIZE);
	if (!conn->rcv_buffer) {
		destroy_byte_snd_buffer(conn->snd_buffer);
		free(conn);
	}

	conn->local_port = id->loc_port;
	conn->extern_port = id->extern_port;
	memcpy(conn->local_addr, id->loc_addr, IPV4_ADDR_LEN);
	memcpy(conn->extern_addr, id->extern_addr, IPV4_ADDR_LEN);

	// 0 used as "previous" value to calculate increase for current
	conn->rcv_buffer->rcv_wnd = 0;

	conn->del_ack_timer = create_timer(create_pkt_fast_snd_pure_ack, conn);
	conn->rto_timer = create_timer(rto_callback, conn);
	conn->zwp_timer = create_timer(zwp_callback, conn);
	conn->snd_zwp = false;
	conn->rto = TCP_INIT_RTO_MS;
	conn->ack_pending = false;
	conn->in_order_full_seg_count = 0;
	conn->tcp_layer = tcp;
	conn->lstnr = NULL;
	return conn;
}

void zwp_callback(void *c)
{
}

void rto_callback(void *c)
{
	struct tcp_ipv4_conn *conn = (struct tcp_ipv4_conn *)c;
	lock_snd_buff(conn->snd_buffer);
	conn->cwnd = conn->snd_mss;
	conn->snd_buffer->rcov_mode = true;
	conn->snd_buffer->rcov_snd_next = conn->snd_buffer->snd_una;
	conn->snd_buffer->rcov_snd_nxt_i = conn->snd_buffer->head;
	conn->rto *= 2;
	unlock_snd_buff(conn->snd_buffer);

	struct socket_manager *mgr =
	    ((struct tcp_context *)conn->tcp_layer->context)->socket_manager;
	notify_socket_readable_snd(mgr, c, &tcp_conn_ops);
}

// initialse seq/ack numbers and options connection based on incoming seg
// called on SYN receive (no cookies)
void server_init_tcp_connection(struct tcp_ipv4_conn *conn, struct tcp_segment *seg)
{
	uint32_t iss = generate_random_iss();
	conn->iss = iss;
	conn->rcv_buffer->rcv_nxt = ntohl(seg->header->seq_num) + seg_seq_len(seg);
	conn->snd_buffer->snd_nxt = iss;
	conn->snd_buffer->snd_una = iss;
	conn->snd_wnd = ntohs(seg->header->window);

	struct tcp_options *opt = seg->options;
	conn->sack_enabled = opt->sack_permitted;
	conn->ts_enabled = opt->ts_present;
	if (opt->mss_present) {
		uint16_t mss = opt->mss;
		conn->snd_mss = mss < TCP_MSS_DEFAULT_FALLBACK ? TCP_MSS_DEFAULT_FALLBACK : mss;
	}
	conn->cwnd = TCP_INIT_CWND_MSS_MULT * conn->snd_mss;
	if (opt->wscale_present) {
		conn->snd_wscale = opt->wscale;
		conn->rcv_wscale = tcp_calc_wndw_scale();
	}
	conn->rcv_buffer->rcv_wnd = calc_rcv_wnd_sws(conn);
}

void create_pkt_fast_snd_pure_ack(void *c)
{
	struct pkt *p = allocate_pkt();
	struct tcp_ipv4_conn *conn = (struct tcp_ipv4_conn *)c;
	tcp_fast_reply_pure_ack(p, conn);
}

// fast reply bypassing send buffer
pkt_result tcp_fast_reply_pure_ack(struct pkt *p, struct tcp_ipv4_conn *conn)
{
	write_pkt_tcp_general_metadata(conn, p);
	p->tcp_flags = TCP_ACK;

	// set SACK
	if (conn->sack_enabled) {
		struct byte_reassembly_rcv_buffer *buff = conn->rcv_buffer;
		size_t count =
		    buff->ooo_count > TCP_HEADER_MAX_SACK ? TCP_HEADER_MAX_SACK : buff->ooo_count;
		for (size_t i = 0; i < count; i++) {
			p->tcp_options->sacks[i] = buff->ooo_segs[i];
		}
	}
	size_t tcp_opt_len = calc_tcp_options_len(p->tcp_options);
	p->tcp_data_offset = ((sizeof(struct tcp_header_no_options) + tcp_opt_len) / 4) << 4;
	p->len = sizeof(struct tcp_header_no_options) + tcp_opt_len;
	p->offset = PKT_SIZE - p->len;

	return conn->tcp_layer->send_down(conn->tcp_layer, p);
}

void tcp_init_packet_addresses(struct pkt *pkt, struct tcp_ipv4_conn *conn)
{
	pkt->src_port = conn->local_port;
	pkt->dest_port = conn->extern_port;
	memcpy(pkt->src_ip, conn->local_addr, IPV4_ADDR_LEN);
	memcpy(pkt->dest_ip, conn->extern_addr, IPV4_ADDR_LEN);
}

// write addressing + tcp seq, window and timestamp echo
// tcp conn state must already reflect state after last incoming segment
// does not set pkt offset or tcp data offset
// pure ack send call or data send call must add relevant options, flags and set offsets/data
void write_pkt_tcp_general_metadata(struct tcp_ipv4_conn *conn, struct pkt *p)
{
	tcp_init_packet_addresses(p, conn);
	tcp_lock_conn(conn);
	p->tcp_seq = conn->snd_buffer->snd_nxt;
	p->tcp_ack = conn->rcv_buffer->rcv_nxt;
	p->rcv_window = calc_rcv_wnd_sws(conn);
	p->route = conn->route;

	// only timestamp is general option
	// SACK in pure fast_send_pure_ack
	// MSS and wscale in handshake
	if (conn->ts_enabled)
		p->tcp_options->tsecr = conn->ts_recent;
	tcp_unlock_conn(conn);
}

void tcp_transition_to_state(struct tcp_ipv4_conn *conn, tcp_connection_state state)
{
	pthread_mutex_lock(&conn->lock);
	conn->state = state;
	pthread_mutex_unlock(&conn->lock);
}

void tcp_retain_conn(void *s)
{
	struct tcp_ipv4_conn *conn = (struct tcp_ipv4_conn *)s;
	retain_tcp_conn(conn);
}

void retain_tcp_conn(struct tcp_ipv4_conn *conn)
{
	pthread_mutex_lock(&(conn->lock));
	conn->ref_count++;
	pthread_mutex_unlock(&(conn->lock));
}

void tcp_release_conn(void *s)
{
	struct tcp_ipv4_conn *conn = (struct tcp_ipv4_conn *)s;
	release_tcp_conn(conn);
}

void release_tcp_conn(struct tcp_ipv4_conn *conn)
{
	bool should_destroy = false;
	pthread_mutex_lock(&(conn->lock));

	conn->ref_count--;
	if (conn->ref_count <= 0)
		should_destroy = true;

	pthread_mutex_unlock(&(conn->lock));
	if (should_destroy)
		destroy_tcp_conn(conn);
}

void tcp_lock_conn(void *s)
{
	struct tcp_ipv4_conn *conn = (struct tcp_ipv4_conn *)s;
	pthread_mutex_lock(&conn->lock);
}

void tcp_unlock_conn(void *s)
{
	struct tcp_ipv4_conn *conn = (struct tcp_ipv4_conn *)s;
	pthread_mutex_unlock(&conn->lock);
}

bool tcp_conn_is_snd_queued(void *s)
{
	return ((struct tcp_ipv4_conn *)s)->queued_for_snd;
}

void tcp_conn_set_snd_queued(void *s, bool v)
{
	((struct tcp_ipv4_conn *)s)->queued_for_snd = v;
}

void destroy_tcp_conn(struct tcp_ipv4_conn *conn)
{
	pthread_mutex_lock(&conn->lock);
	destroy_byte_rcv_buffer(conn->rcv_buffer);
	destroy_byte_snd_buffer(conn->snd_buffer);
	free(conn->del_ack_timer);
	free(conn->rto_timer);
	free(conn->zwp_timer);
	pthread_mutex_destroy(&conn->lock);
	free(conn);
}

bool is_tcp_send_ready(void *s)
{
	struct tcp_ipv4_conn *conn = (struct tcp_ipv4_conn *)s;
	struct byte_snd_buffer *buff = conn->snd_buffer;
	lock_snd_buff(buff);
	uint32_t snd_seq = !buff->rcov_mode ? buff->snd_nxt : buff->rcov_snd_next;
	uint32_t window = usable_window(conn);
	if (window == 0)
		return false;

	// in general we want to send MSS
	uint32_t min_bytes_to_send = conn->snd_mss;

	// unless a SYN/FIN is coming up
	uint32_t ctrl_seq = buff->ctrl[0].seq;
	uint32_t ctrl_delta = (ctrl_seq - buff->snd_una);
	uint32_t snd_delta = (snd_seq - buff->snd_una);

	bool ctrl_seq_upcoming = ctrl_delta > snd_delta; // else it's stored for retransmissions?
	if (ctrl_seq_upcoming && window >= ctrl_delta + 1) {
		unlock_snd_buff(buff);
		return true;
	}

	uint32_t data_rdy_to_send = snd_delta;

	// subtract sacked_bytes before snd_seq
	for (size_t i = 0; i < buff->sack_blocks_count; i++) {
		if (buff->sack_blocks[i].start_seq < snd_seq)
			data_rdy_to_send -= buff->sack_blocks[i].end_seq - buff->sack_blocks[i].start_seq;
	}
	unlock_snd_buff(buff);
	return data_rdy_to_send >= min_bytes_to_send;
}