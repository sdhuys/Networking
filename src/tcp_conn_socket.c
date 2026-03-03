#include "tcp_conn_socket.h"
#include "tcp.h"

const struct socket_ops tcp_conn_ops = {.is_snd_queued = tcp_is_snd_queued,
					.set_snd_queued = tcp_set_snd_queued,
					.retain = tcp_retain_conn,
					.release = tcp_release_conn,
					.write_to_snd_buffer = NULL,
					.read_rcv_buffer = NULL,
					.unlock = tcp_unlock_conn,
					.lock = tcp_lock_conn,
					.try_get_pkt = tcp_try_get_pkt,
					.send_pkt = tcp_send_packet,
					.close = NULL};

pkt_result process_tcp_segment(struct pkt *p, struct tcp_segment *seg, struct tcp_ipv4_conn *conn)
{
	uint32_t seg_seq = ntohl(seg->header->seq_num);
	uint32_t seg_ack = ntohl(seg->header->ack_num);
	uint16_t flags = seg->header->flags;

	uint32_t rcv_next = conn->rcv_buffer->rcv_nxt;
	uint32_t rcv_wnd = conn->rcv_buffer->rcv_wnd;
	size_t s_len = seg_seq_len(seg);

	struct tcp_context *ctx = (struct tcp_context *)conn->tcp_layer->context;
	struct timer_manager *tmgr = ctx->rx_timer_mgr;

	// RST processing, cleanup
	if (flags & TCP_RST) {
		remove_from_tcp_conn_hashtable(conn->htable, conn);
		tcp_transition_to_state(conn, CLOSED);
		// notify threads waiting to read/write to cancel
		pthread_cond_broadcast(&conn->snd_buffer->cond);
		pthread_cond_broadcast(&conn->rcv_buffer->cond);
		return INC_RST_CONN_DEAD;
	}

	// window Validation
	bool in_window = false;
	if (s_len == 0) {
		// accepting pure acks if they aren't "from the future"
		in_window = tcp_seq_before(seg_seq, rcv_next + rcv_wnd + (rcv_wnd == 0));
	} else {
		if (rcv_wnd > 0) {
			uint32_t seg_end = seg_seq + s_len - 1;
			in_window = tcp_seq_before(seg_seq, rcv_next + rcv_wnd) &&
				    tcp_seq_after_eq(seg_end, rcv_next);
		} else {
			// zero window, trigger pure ack responses (window probe replies)
			in_window = false;
		}
	}

	if (!in_window) {
		// challenge ack or window probe reply
		if (s_len > 0) {
			tcp_fast_reply_pure_ack(p, conn);
		}
		return TCP_SEG_OUT_OF_WNDW_RANGE;
	}

	// SYN handling
	if (flags & TCP_SYN) {
		if (conn->state == SYN_SENT) {
			conn->irs = seg_seq;
			conn->rcv_buffer->rcv_nxt = seg_seq + 1;

			if (!(flags & TCP_ACK)) {
				// simultaneous open: received SYN while expecting SYN-ACK
				// trigger SYN-retransmission, SYN_RECEIVED state will append ACK
				tcp_transition_to_state(conn, SYN_RECEIVED);
				rto_callback(conn);
				return TCP_SIMULTANEOUS_OPEN;
			}
			// else (SYN-ACK) => fallthrough to ACK processing below to finalise
			// handshake

		} else if (conn->state == SYN_RECEIVED && seg_seq == conn->irs) {
			// duplicate SYN: retrigger SYN-ACK sending
			rto_callback(conn);
			return RCOV_SYN_ACK_TO_SND_BUFFER;
		} else if (conn->state >= ESTABLISHED) {
			// unexpected SYN in established session
			tcp_fast_reply_rst(conn->tcp_layer, p, seg);
			return RST_UNEXPECTED_SYN;
		}
	}

	// ACK processing
	if (flags & TCP_ACK) {
		lock_snd_buff(conn->snd_buffer);
		bool valid_new_ack = tcp_seq_after(seg_ack, conn->snd_buffer->snd_una) &&
				     tcp_seq_before_eq(seg_ack, conn->snd_buffer->snd_nxt);
		bool dupe_ack = (seg_ack == conn->snd_buffer->snd_una);

		if (valid_new_ack || dupe_ack) {
			switch (conn->state) {
			case SYN_SENT:
				if (valid_new_ack && (seg_ack == conn->iss + 1)) {
					conn->irs = seg_seq;
					conn->rcv_buffer->rcv_nxt = seg_seq + 1;
					tcp_transition_to_state(conn, ESTABLISHED);
					conn->snd_buffer->snd_una = seg_ack;
					conn->snd_buffer->ctrl_count--;
				}
				break;

			case SYN_RECEIVED:
				if (valid_new_ack) {
					tcp_transition_to_state(conn, ESTABLISHED);
					conn->snd_buffer->snd_una = seg_ack;
					conn->snd_buffer->ctrl_count--;
				}
				break;

			default:
				if (valid_new_ack) {
					struct byte_snd_buffer *sb = conn->snd_buffer;
					uint32_t old_una = sb->snd_una;
					uint32_t data_ackd = seg_ack - old_una;

					// update snd_una and head
					sb->snd_una = seg_ack;
					sb->used_bytes -= data_ackd;
					sb->head = (sb->head + data_ackd) & (sb->capacity - 1);

					// remove SACK blocks that are overtaken by progressed
					// snd_una
					int sack = 0;
					for (int i = 0; i < sb->sack_blocks_count; i++) {
						// only keep blocks that start after snd_una
						if (tcp_seq_after(sb->sack_blocks[i].start_seq,
								  sb->snd_una)) {
							sb->sack_blocks[sack++] =
							    sb->sack_blocks[i];
						}
					}
					sb->sack_blocks_count = sack;

					// process new sack blocks
					size_t sack_count = seg->options->sack_block_count;
					struct ooo_seg *sacks = seg->options->sacks;
					if (seg->options->sack_block_count > 0) {
						for (int i = 0; i < sack_count; i++) {
							uint32_t s_start = sacks[i].start_seq;
							uint32_t s_end = sacks[i].end_seq;

							// only add SACKs that are
							// "ahead" of our cumulative ACK
							if (tcp_seq_after(s_end, seg_ack) &&
							    tcp_seq_before_eq(s_end, sb->snd_nxt)) {

								///////////////////////////
								// ADD/MERGE BLOCKS
							}
						}
					}

					// retransmission timer
					cancel_timer(tmgr, conn->rto_timer);
					if (sb->snd_nxt != sb->snd_una) {
						start_timer(tmgr, conn->rto_timer, conn->rto);
					}

					pthread_cond_broadcast(&sb->cond);
					pthread_cond_broadcast(&conn->snd_buffer->cond);

					// update peer's window and reset duplicate count
					conn->snd_wndw = ntohs(seg->header->window);
					conn->dup_ack_cnt = 0;

				} else if (dupe_ack && s_len == 0) {

					conn->dup_ack_cnt++;
					if (conn->dup_ack_cnt == 3)
						rto_callback(conn); // CHANGE TO SEPARATE FAST
								    // RETRANSMIT CALL!
				}
				break;
			}
		} else if (tcp_seq_after(seg_ack, conn->snd_buffer->snd_nxt)) {
			// ACK out of sync, send challenge ACK
			tcp_fast_reply_pure_ack(p, conn);
			unlock_snd_buff(conn->snd_buffer);
			return TCP_ACK_OUT_OF_SYNC;
		}
		unlock_snd_buff(conn->snd_buffer);
	}

	// data handling: trimming is done by rcv_buffer_write_tcp_segment
	if (conn->state >= ESTABLISHED && seg->payload_len > 0) {
		lock_rcv_buff(conn->rcv_buffer);
		rcv_buffer_write_tcp_segment(conn->rcv_buffer, seg);
		unlock_rcv_buff(conn->rcv_buffer);

		// delayed ACK logic: 1st packet starts timer, 2nd packet triggers immediate ACK
		if (!conn->ack_pending) {
			conn->ack_pending = true;
			start_timer(tmgr, conn->del_ack_timer, TCP_DEL_ACK_MS);
		} else {
			cancel_timer(tmgr, conn->del_ack_timer);
			tcp_fast_reply_pure_ack(p, conn);
			conn->ack_pending = false;
		}
	}

	// FIN handling
	if (flags & TCP_FIN) {
		conn->rcv_buffer->rcv_nxt++; // add FIN ghost byte
		printf("FIN ACKING \n");

		tcp_fast_reply_pure_ack(p, conn);
		if (conn->state == ESTABLISHED)
			tcp_transition_to_state(conn, CLOSE_WAIT);
		else if (conn->state == FIN_WAIT_1)
			tcp_transition_to_state(conn, (flags & TCP_ACK) ? TIME_WAIT : CLOSING);
		else if (conn->state == FIN_WAIT_2) {
			tcp_transition_to_state(conn, TIME_WAIT);
			remove_from_tcp_conn_hashtable(conn->htable, conn);
			struct tcp_ipv4_conn_htable *cls_wait =
			    ctx->socket_manager->tcp_ipv4_conn_time_wait_htable;
			add_to_tcp_conn_hashtable(cls_wait, conn);
		}
	}

	return TCP_SEG_PROCESSED;
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

	conn->del_ack_timer = create_timer(delayed_ack_callback, conn);
	conn->rto_timer = create_timer(rto_callback, conn);
	conn->zwp_timer = create_timer(zwp_callback, conn);
	conn->snd_zwp = false;
	conn->rto = TCP_INIT_RTO_MS;
	conn->ack_pending = false;
	conn->in_order_full_seg_count = 0;
	conn->tcp_layer = tcp;
	conn->lstnr = NULL;
	get_route(((struct tcp_context *)tcp->context)->routing_tbl, id->extern_addr, &conn->route);
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
	conn->irs = ntohl(seg->header->seq_num);
	conn->rcv_buffer->rcv_nxt = conn->irs + seg_seq_len(seg);
	conn->snd_buffer->snd_nxt = iss;
	conn->snd_buffer->snd_una = iss;
	conn->snd_wndw = ntohs(seg->header->window);

	struct tcp_options *opt = seg->options;
	conn->sack_enabled = opt->sack_permitted;
	conn->ts_enabled = opt->ts_present;
	conn->wscale_enabled = opt->wscale_present;
	if (opt->mss_present) {
		uint16_t mss = opt->mss;
		conn->snd_mss = mss < TCP_MSS_DEFAULT_FALLBACK ? TCP_MSS_DEFAULT_FALLBACK : mss;
	}
	conn->cwnd = TCP_INIT_CWND_MSS_MULT * conn->snd_mss;
	if (opt->wscale_present) {
		conn->snd_wscale = opt->wscale;
		conn->rcv_wscale = tcp_calc_wndw_scale();
	}
	if (opt->ts_present)
		conn->ts_recent = opt->tsval;

	conn->rcv_buffer->rcv_wnd = calc_rcv_wnd_sws(conn);
}

void delayed_ack_callback(void *c)
{
	struct pkt *p = allocate_pkt();
	struct tcp_ipv4_conn *conn = (struct tcp_ipv4_conn *)c;
	tcp_fast_reply_pure_ack(p, conn);
}

// fast reply bypassing send buffer
pkt_result tcp_fast_reply_pure_ack(struct pkt *p, struct tcp_ipv4_conn *conn)
{
	printf("\n\n!!!! FAST ACK REPLY \n\n");

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

	p->len = sizeof(struct tcp_header_no_options) + calc_tcp_options_len(p->tcp_options);
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
// pure ack send call or data send call must add relevant options, flags and set
// offsets/data
void write_pkt_tcp_general_metadata(struct tcp_ipv4_conn *conn, struct pkt *p)
{
	tcp_init_packet_addresses(p, conn);
	tcp_lock_conn(conn);
	p->tcp_seq = conn->snd_buffer->rcov_mode ? conn->snd_buffer->rcov_snd_next
						 : conn->snd_buffer->snd_nxt;
	p->tcp_ack = conn->rcv_buffer->rcv_nxt;
	p->rcv_window = calc_rcv_wnd_sws(conn);
	p->route = conn->route;
	p->protocol = P_TCP;
	p->tcp_flags = 0;

	// only timestamp is general option
	// SACK in pure fast_send_pure_ack
	// MSS and wscale, SACK permitted in handshake
	if (conn->ts_enabled) {
		p->tcp_options->ts_present = true;
		p->tcp_options->tsecr = conn->ts_recent;
	}

	// general settings, can be overwritten in handshake or pure acks
	// no negotiations
	p->tcp_options->sack_permitted = false;
	p->tcp_options->mss_present = false;
	p->tcp_options->wscale_present = false;
	// no sack blocks
	p->tcp_options->sack_block_count = 0;

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

// caller must hold send buffer lock
struct pkt *create_tcp_packet(struct tcp_ipv4_conn *conn, size_t seq, size_t seq_len)
{
	printf("\nCREATING PACKET\n");
	struct pkt *p = allocate_pkt();
	write_pkt_tcp_general_metadata(conn, p);

	size_t payload_len = seq_len;

	struct byte_snd_buffer *b = conn->snd_buffer;
	for (uint8_t i = 0; i < b->ctrl_count; i++)
		if (tcp_seq_after_eq(b->ctrl[i].seq, seq) &&
		    tcp_seq_before(b->ctrl[i].seq, seq + seq_len)) {
			p->tcp_flags |= b->ctrl[i].flags;
			payload_len--;
		}

	if (conn->state != SYN_SENT && conn->state != FIN_WAIT_1)
		p->tcp_flags |= TCP_ACK;

	// add handshake options
	if (conn->state == SYN_SENT || conn->state == SYN_RECEIVED) {
		if (conn->wscale_enabled) {
			p->tcp_options->wscale_present = true;
			p->tcp_options->wscale = conn->rcv_wscale;
		}
		p->tcp_options->mss = conn->snd_mss;
		p->tcp_options->mss_present = true;
		if (conn->sack_enabled)
			p->tcp_options->sack_permitted = true;
	}
	if (conn->ts_enabled)
		p->tcp_options->ts_present = true;

	// SACK blocks only in pure ACKs!

	// write data to packet buffer
	p->len = payload_len + sizeof(struct tcp_header_no_options) +
		 calc_tcp_options_len(p->tcp_options);
	p->offset = PKT_SIZE - p->len;
	copy_bytes_to_snd_from_snd_buff(conn->snd_buffer, p->data + p->offset, payload_len);

	////////////////// DO THIS AFTER ATUALLY SENDING THE PACKET ?!!!//////////////
	if (conn->snd_buffer->rcov_mode) {
		conn->snd_buffer->rcov_snd_next += seq_len;
		conn->snd_buffer->rcov_snd_nxt_i =
		    (conn->snd_buffer->rcov_snd_nxt_i + payload_len) &
		    (conn->snd_buffer->capacity - 1);
		if (conn->snd_buffer->rcov_snd_next >= conn->snd_buffer->snd_nxt)
			conn->snd_buffer->rcov_mode = false;
	} else {
		conn->snd_buffer->snd_nxt += seq_len;
		conn->snd_buffer->snd_nxt_i =
		    (conn->snd_buffer->snd_nxt_i + payload_len) & (conn->snd_buffer->capacity - 1);
	}
	///////////////////////////////////////////////////////

	printf("\nRETURNING PACKET\n");

	return p;
}

struct pkt *tcp_try_get_pkt(void *s)
{
	struct tcp_ipv4_conn *conn = (struct tcp_ipv4_conn *)s;

	if (conn->state == CLOSED)
		return NULL;

	struct byte_snd_buffer *buff = conn->snd_buffer;
	struct pkt *p;

	lock_snd_buff(buff);
	uint32_t snd_seq = !buff->rcov_mode ? buff->snd_nxt : buff->rcov_snd_next;
	uint32_t window = usable_window(conn);
	printf("WINDOW = %d \n", window);
	if (window == 0) {
		unlock_snd_buff(buff);
		return NULL;
	}

	uint32_t tail_seq = buff->snd_una + (uint32_t)buff->used_bytes + buff->ctrl_count;
	uint32_t bytes_ready = tail_seq - snd_seq;

	printf("snd_una: %u, used_bytes: %d, ctrl_count: %u \n",
	       buff->snd_una,
	       (uint32_t)buff->used_bytes,
	       buff->ctrl_count);
	printf("BYTES READY = %u \n", bytes_ready);

	if (bytes_ready <= 0) {
		unlock_snd_buff(buff);
		return NULL;
	}

	// in general we want to send MSS
	uint32_t min_bytes_snd = conn->snd_mss;
	// minus timestamp option length
	if (conn->ts_enabled)
		min_bytes_snd -= TCP_OP_TS_LEN;

	// unless a SYN/FIN is coming up, then we just want to be able to send the amount of
	// bytes it takes to reach the control seq
	if (buff->ctrl_count > 0 && tcp_seq_after_eq(buff->ctrl[0].seq, snd_seq)) {
		uint32_t len_to_reach_ctrl = (buff->ctrl[0].seq - snd_seq) + 1;
		if (window >= len_to_reach_ctrl) {
			p = create_tcp_packet(conn, snd_seq, len_to_reach_ctrl);
			unlock_snd_buff(buff);
			return p;
		}
	}

	if (buff->rcov_mode) {
		bool is_sack_upcoming = false;
		uint32_t gap_len;
		// find length of first gap from snd_seq to upcoming sack block
		for (size_t i = 0; i < buff->sack_blocks_count; i++) {
			if (tcp_seq_before(snd_seq, buff->sack_blocks[i].start_seq)) {
				is_sack_upcoming = true;

				gap_len = (buff->sack_blocks[i].start_seq - snd_seq);
				// if gap can be closed by sending less bytes than MSS,
				// don't wait for MSS wdnw
				min_bytes_snd = gap_len < min_bytes_snd ? gap_len : min_bytes_snd;
				break;
			}
		}
		// gap is until snd_next
		if (!is_sack_upcoming) {
			gap_len = buff->snd_nxt - snd_seq;
			min_bytes_snd = gap_len < min_bytes_snd ? gap_len : min_bytes_snd;
		}
	}
	if (bytes_ready < min_bytes_snd)
		min_bytes_snd = bytes_ready;

	if (window < min_bytes_snd) {
		unlock_snd_buff(buff);
		return NULL;
	}

	p = create_tcp_packet(conn, snd_seq, min_bytes_snd);
	return p;
}

pkt_result tcp_send_packet(struct stack *stack, struct pkt *p)
{
	pkt_result r = stack->tcp_layer->send_down(stack->tcp_layer, p);

	// edit rcv_next, start timers, etc?
	return r;
}

bool tcp_is_snd_queued(void *s)
{
	return ((struct tcp_ipv4_conn *)s)->queued_for_snd;
}

// caller must hold lock!
void tcp_set_snd_queued(void *s, bool v)
{
	((struct tcp_ipv4_conn *)s)->queued_for_snd = v;
}
