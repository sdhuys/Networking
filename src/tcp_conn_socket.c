#include "tcp_conn_socket.h"
#include "buffer_pool.h"
#include "container_of.h"
#include "ipv4.h"
#include "nw_layer.h"
#include "pkt.h"
#include "routing_table.h"
#include "send_request.h"
#include "socket_manager.h"
#include "stack.h"
#include "tcp.h"
#include "tcp_conn_htable.h"
#include "tcp_listener_socket.h"
#include "tcp_options.h"
#include "tcp_segment.h"
#include "timer.h"
#include "window_helpers.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>

const struct socket_ops tcp_conn_ops = {.is_snd_queued = tcp_is_snd_queued,
					.set_snd_queued = tcp_set_snd_queued,
					.retain = tcp_retain_conn,
					.release = tcp_release_conn,
					.write_to_snd_buffer = tcp_write_to_snd_buff,
					.read_rcv_buffer = tcp_read_from_rcv_buff,
					.unlock = tcp_unlock_conn,
					.lock = tcp_lock_conn,
					.try_get_pkt = tcp_try_get_pkt,
					.send_pkt = tcp_send_packet,
					.close = tcp_close_conn,
					.accept = NULL,
					.end_snd = tcp_end_snd};

static void rst_connection(struct tcp_ipv4_conn *conn)
{
	tcp_transition_to_state(conn, CLOSED);

	struct tcp_ipv4_conn_htable *htable =
	    ((struct tcp_context *)conn->tcp_layer->context)->socket_manager->tcp_ipv4_conn_htable;
	remove_from_tcp_conn_hashtable(htable, conn);
}

pkt_result process_tcp_segment(struct pkt *p, struct tcp_segment *seg, struct tcp_ipv4_conn *conn)
{
	uint32_t seg_seq = ntohl(seg->header->seq_num);
	uint32_t seg_ack = ntohl(seg->header->ack_num);
	uint16_t flags = seg->header->flags;

	uint32_t snd_next = conn->snd_buffer.snd_nxt;
	uint32_t snd_una = conn->snd_buffer.snd_una;
	uint32_t rcv_next = conn->rcv_buffer.rcv_nxt;
	uint32_t scaled_rcv_wnd = conn->rcv_buffer.rcv_wnd << conn->rcv_buffer.rcv_wscale;

	size_t s_len = seg_seq_len(seg);

	struct tcp_context *ctx = (struct tcp_context *)conn->tcp_layer->context;
	struct socket_manager *smgr = ctx->socket_manager;
	struct timer_manager *tmgr = ctx->timer_mgr;

	// window Validation
	bool in_window = false;
	if (conn->state == SYN_SENT)
		in_window = true;
	else if (s_len == 0) {
		// accepting pure acks if they aren't "from the future"
		in_window =
		    tcp_seq_before(seg_seq, rcv_next + scaled_rcv_wnd + (scaled_rcv_wnd == 0));
	} else {
		if (scaled_rcv_wnd > 0) {
			uint32_t seg_end = seg_seq + s_len - 1;
			in_window = tcp_seq_before(seg_seq, rcv_next + scaled_rcv_wnd) &&
				    tcp_seq_after_eq(seg_end, rcv_next);
		} else {
			// zero window, trigger pure ack responses (window probe replies)
			in_window = false;
		}
	}

	if (!in_window) {
		// challenge ack or window probe reply
		if (s_len > 0 && (flags & TCP_SYN) && !(flags & TCP_ACK) &&
		    conn->state == SYN_RECEIVED &&
		    seg_seq == conn->irs) { // duplicate SYN: retrigger SYN-ACK sending
			start_timer(tmgr, conn->rto_timer, 0);
			return RCOV_SYN_ACK_TO_SND_BUFFER;
		}
		if (s_len > 0) {
			printf("\nTCP SEG NOT IN WINDOW, Sending challenge ACK/Replying to window "
			       "probe! \n");
			tcp_fast_reply_pure_ack(p, conn);
			// our previous ACK lost, restart timer
			if (conn->state == TIME_WAIT && flags & TCP_FIN)
				start_timer(tmgr, conn->time_wait_timer, TCP_TIMEWAIT_LEN);
			return TCP_SEG_OUT_WNDW_RNG_ACK_SNT;
		}
		return TCP_SEG_OUT_OF_WNDW_RANGE;
	}
	// RST processing
	if (flags & TCP_RST) {
		if (seg_seq == rcv_next) {
			rst_connection(conn);
			return INC_RST_CONN_DEAD;
		}
		// per RFC 5961
		if (conn->state != SYN_SENT && in_window) {
			tcp_fast_reply_pure_ack(p, conn);
			return INC_RST_CHALL_ACK_SENT;
		}
		return INVALID_RST_DROPPED;
	}

	bool immediate_ack = false;
	// SYN handling
	if (flags & TCP_SYN) {
		immediate_ack = true;
		if (conn->state == SYN_SENT) {
			// init connection
			conn->irs = seg_seq;
			conn->rcv_buffer.rcv_nxt = seg_seq + 1;
			conn->rcv_buffer.consumed_seq = seg_seq;
			conn->ts_enabled = seg->options->ts_present;
			conn->sack_enabled = seg->options->sack_permitted;
			if (seg->options->mss_present) {
				conn->snd_mss =
				    seg->options->mss - (conn->ts_enabled ? TCP_OP_TS_LEN : 0);
				conn->snd_buffer.cwnd = TCP_INIT_CWND_MSS_MULT * conn->snd_mss;
			}

			if (!(flags & TCP_ACK)) {
				// simultaneous open: received SYN while expecting SYN-ACK
				// trigger SYN-retransmission, SYN_RECEIVED state will
				// append ACK
				tcp_transition_to_state(conn, SYN_RECEIVED);
				start_timer(tmgr, conn->rto_timer, 0);
				return TCP_SIMULTANEOUS_OPEN;
			}
			// else (SYN-ACK) => fallthrough to ACK processing below to finalise
			// handshake

		} else if (conn->state >= ESTABLISHED) {
			// unexpected SYN in established session
			tcp_fast_reply_rst(conn->tcp_layer, p, seg);
			rst_connection(conn);
			return RST_UNEXPECTED_SYN;
		}
	}

	// ACK processing
	if (flags & TCP_ACK) {
		bool valid_new_ack =
		    tcp_seq_after(seg_ack, snd_una) && tcp_seq_before_eq(seg_ack, snd_next);
		bool dupe_ack = (seg_ack == snd_una);

		if (valid_new_ack || dupe_ack) {

			struct byte_snd_buffer *sb = &conn->snd_buffer;
			lock_snd_buff(sb);
			sb->snd_wndw = ntohs(seg->header->window);

			switch (conn->state) {
			case SYN_SENT:
				if (valid_new_ack && (seg_ack == conn->iss + 1)) {
					conn->snd_buffer.snd_una = seg_ack;
					conn->snd_buffer.ctrl_count--;
					if (flags & TCP_SYN)
						tcp_transition_to_state(conn, ESTABLISHED);
				}
				break;

			case SYN_RECEIVED:
				if (valid_new_ack) {
					tcp_transition_to_state(conn, ESTABLISHED);
					conn->snd_buffer.snd_una = seg_ack;
					conn->snd_buffer.ctrl_count--;
				}
				break;

			default:
				if (valid_new_ack) {
					uint32_t old_una = sb->snd_una;
					uint32_t data_ackd = seg_ack - old_una;

					// substract ghost byte if FIN acked
					if (conn->state == FIN_WAIT_1 || conn->state == CLOSING ||
					    conn->state == LAST_ACK) {
						for (uint8_t i = 0; i < sb->ctrl_count; i++) {
							if (sb->ctrl[i].flags == TCP_FIN &&
							    tcp_seq_after(seg_ack,
									  sb->ctrl[i].seq)) {
								tcp_transition_to_state(conn,
											FIN_WAIT_2);
								data_ackd--;
								sb->ctrl_count--;
								break;
							}
						}
					}
					// update snd_una and head
					update_snd_nxt_head(sb, seg_ack, data_ackd);

					// cwnd growth
					uint32_t mss = conn->snd_mss;
					uint32_t growth = data_ackd > 2 * mss ? 2 * mss : data_ackd;
					switch (sb->c_state) {
					case CONG_AVOIDANCE:
						sb->cwnd += growth * growth / sb->cwnd;
						break;
					case SLOW_START:
						sb->cwnd += growth;
						if (sb->cwnd >= sb->ssthresh)
							sb->c_state = CONG_AVOIDANCE;
						break;
					case FAST_RECOVERY:
						sb->c_state = CONG_AVOIDANCE;
						sb->cwnd = sb->ssthresh;
					}
					conn->dup_ack_cnt = 0;

					// remove SACK blocks that are overtaken by
					// progressed snd_una
					if (sb->sack_blocks_count > 0) {
						size_t overtaken_sacks =
						    bin_search_seq_after_eq_indx(
							sb->snd_una,
							sb->sack_blocks,
							sb->sack_blocks_count);

						if (overtaken_sacks < sb->sack_blocks_count &&
						    sb->sack_blocks[overtaken_sacks].start_seq ==
							sb->snd_una)
							overtaken_sacks++;

						if (overtaken_sacks > 0) {
							memmove(&sb->sack_blocks,
								&sb->sack_blocks[overtaken_sacks],
								(sb->sack_blocks_count -
								 overtaken_sacks) *
								    sizeof(struct ooo_seg));
							sb->sack_blocks_count -= overtaken_sacks;
						}
					}

					// pure dupe ack, no data
				} else if (s_len == 0) {
					switch (sb->c_state) {
					case FAST_RECOVERY:
						sb->cwnd += conn->snd_mss;
						break;
					default:
						conn->dup_ack_cnt++;
						if (conn->dup_ack_cnt == 3)
							fast_recovery(conn);
						break;
					}
				}

				// process new sack blocks
				size_t sack_count = seg->options->sack_block_count;
				struct ooo_seg *sacks = seg->options->sacks;
				for (size_t i = 0; i < sack_count; i++) {
					uint32_t s_start = sacks[i].start_seq;
					uint32_t s_end = sacks[i].end_seq;

					if (should_store_sack_block(
						sb, s_start, s_end, sb->snd_una)) {
						size_t idx = bin_search_seq_after_eq_indx(
						    sacks[i].start_seq,
						    sb->sack_blocks,
						    sb->sack_blocks_count);

						insert_ooo_segment(sb->sack_blocks,
								   &(sb->sack_blocks_count),
								   sb->sack_capacity,
								   sacks[i],
								   idx);
					}
				}
				break;
			}
			unlock_snd_buff(sb);

			if (valid_new_ack) {
				// retransmission timer
				cancel_timer(tmgr, conn->rto_timer);
				conn->rto = TCP_INIT_RTO_MS;
				if (sb->snd_nxt != sb->snd_una) {
					start_timer(tmgr, conn->rto_timer, conn->rto);
				}
				// notify send buffer we can overwrite acked data
				pthread_cond_broadcast(&sb->cond);
				// add socket to tx queue to send out potential new packets
				notify_socket_readable_snd(smgr, conn, &tcp_conn_ops);
			}

		} else if (tcp_seq_after(seg_ack, snd_next)) {
			// ACK out of sync, send challenge ACK
			tcp_fast_reply_pure_ack(p, conn);
			return TCP_ACK_OUT_OF_SYNC;
		}
	}

	// data handling: trimming is done by rcv_buffer_write_tcp_segment
	if (conn->state >= ESTABLISHED && seg->payload_len > 0) {
		rcv_buffer_write_tcp_segment(&conn->rcv_buffer, seg, &immediate_ack);
		conn->rcv_buffer.rcv_wnd = calc_rcv_wnd_sws(conn);
		// delayed ACK logic: 1st packet starts timer, 2nd packet triggers immediate
		// ACK
		if (!immediate_ack && !conn->ack_pending) {
			conn->ack_pending = true;
			start_timer(tmgr, conn->del_ack_timer, TCP_DEL_ACK_MS);
		} else {
			immediate_ack = true;
		}
	}
	// FIN handling
	if (flags & TCP_FIN) {
		uint32_t fin_seq = seg_seq + seg->payload_len;
		conn->rcv_buffer.fin_seq = fin_seq;
		conn->rcv_buffer.fin_received = true;
	}

	if (conn->rcv_buffer.fin_received && conn->rcv_buffer.fin_seq == conn->rcv_buffer.rcv_nxt) {
		conn->rcv_buffer.rcv_nxt++; // add FIN ghost byte
		immediate_ack = true;
		if (conn->state == ESTABLISHED)
			tcp_transition_to_state(conn, CLOSE_WAIT);
		else if (conn->state == FIN_WAIT_1) {
			bool fin_acked =
			    (flags & TCP_ACK) &&
			    (seg_ack ==
			     snd_next); // no more data after FIN, so snd_next is FIN's seq + 1
			tcp_transition_to_state(conn, fin_acked ? TIME_WAIT : CLOSING);

		} else if (conn->state == FIN_WAIT_2) {
			tcp_transition_to_state(conn, TIME_WAIT);
		}
		pthread_cond_broadcast(&conn->rcv_buffer.cond);
	}
	if (immediate_ack) {
		tcp_fast_reply_pure_ack(p, conn);
		return TCP_IMMEDIATE_ACK_SNT;
	}
	return TCP_SEG_PROCESSED;
}

// enqueues the tcp connection sock to TX worker queue
// after dequeing actual ops.send_packet will check state and append ACK if needed
void tcp_syn_to_snd_buff(struct tcp_ipv4_conn *conn)
{
	sndbuf_insert_ghost_byte(&conn->snd_buffer, TCP_SYN);
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
	if (pthread_mutex_init(&conn->lock, NULL) < 0) {
		free(conn);
		return NULL;
	}
	if (pthread_cond_init(&conn->estblshd_cond, NULL) < 0) {
		pthread_mutex_destroy(&conn->lock);
		free(conn);
		return NULL;
	}

	if (init_byte_snd_buffer(&conn->snd_buffer, TCP_DEFAULT_BUFFER_SIZE) < 0 ||
	    init_byte_rcv_buffer(&conn->rcv_buffer, TCP_DEFAULT_BUFFER_SIZE) < 0) {
		destroy_tcp_conn(conn);
		return NULL;
	}

	conn->del_ack_timer = create_timer(delayed_ack_callback, conn);
	conn->rto_timer = create_timer(rto_callback, conn);
	conn->zwp_timer = create_timer(zwp_callback, conn);
	conn->time_wait_timer = create_timer(time_wait_callback, conn);

	if (!conn->del_ack_timer || !conn->rto_timer || !conn->zwp_timer ||
	    !conn->time_wait_timer) {
		destroy_tcp_conn(conn);
		return NULL;
	}

	conn->ref_count = 0;

	conn->local_port = id->loc_port;
	conn->extern_port = id->extern_port;
	memcpy(conn->local_addr, id->loc_addr, IPV4_ADDR_LEN);
	memcpy(conn->extern_addr, id->extern_addr, IPV4_ADDR_LEN);

	// 0 used as "previous" value to calculate increase for current
	conn->rcv_buffer.rcv_wnd = 0;
	conn->rcv_buffer.rcv_wscale = tcp_calc_wndw_scale();

	conn->snd_zwp = false;
	conn->rto = TCP_INIT_RTO_MS;
	conn->ack_pending = false;
	conn->in_order_full_seg_count = 0;
	conn->tcp_layer = tcp;
	conn->lstnr = NULL;
	conn->snd_buffer.snd_wscale = 0;
	conn->queued_for_snd = false;
	conn->data_timers_cancelled = false;
	if (get_route(
		((struct tcp_context *)tcp->context)->routing_tbl, id->extern_addr, &conn->route)) {
		conn->rcv_mss = conn->route->mtu - sizeof(struct ipv4_header) -
				sizeof(struct tcp_header_no_options);
	} else {
		conn->rcv_mss = TCP_MSS_DEFAULT_FALLBACK;
	}

	return conn;
}

void zwp_callback(void *c)
{
	struct tcp_ipv4_conn *conn = (struct tcp_ipv4_conn *)c;

	pthread_mutex_lock(&conn->lock);
	if (conn->data_timers_cancelled) {
		pthread_mutex_unlock(&conn->lock);
		return;
	}
	pthread_mutex_unlock(&conn->lock);
}

void rto_callback(void *c)
{
	printf("\n        RTO callback! \n \n");
	struct tcp_ipv4_conn *conn = (struct tcp_ipv4_conn *)c;

	pthread_mutex_lock(&conn->lock);
	if (conn->data_timers_cancelled) {
		pthread_mutex_unlock(&conn->lock);
		return;
	}
	conn->dup_ack_cnt = 0;
	pthread_mutex_unlock(&conn->lock);

	struct byte_snd_buffer *sb = &conn->snd_buffer;
	lock_snd_buff(sb);
	sb->c_state = SLOW_START;
	sb->cwnd = conn->snd_mss;
	sb->retransmit = true;
	conn->rto *= 2;
	if (conn->rto > 60000)
		conn->rto = 60000;
	unlock_snd_buff(sb);

	struct socket_manager *mgr =
	    ((struct tcp_context *)conn->tcp_layer->context)->socket_manager;
	notify_socket_readable_snd(mgr, c, &tcp_conn_ops);
}

void time_wait_callback(void *c)
{
	struct tcp_ipv4_conn *conn = (struct tcp_ipv4_conn *)c;
	tcp_transition_to_state(conn, CLOSED);
}

// caller must hold lock
void fast_recovery(struct tcp_ipv4_conn *conn)
{
	printf("\n\n            FAST RETRANSMIT! \n \n");

	struct tcp_context *ctx = (struct tcp_context *)conn->tcp_layer->context;
	cancel_timer(ctx->timer_mgr, conn->rto_timer);

	struct byte_snd_buffer *sb = &conn->snd_buffer;
	sb->c_state = FAST_RECOVERY;
	sb->ssthresh = sb->cwnd / 2 > 2 * conn->snd_mss ? sb->cwnd / 2 : 2 * conn->snd_mss;
	sb->cwnd = sb->ssthresh + 3 * conn->snd_mss;

	sb->retransmit = true;

	struct socket_manager *mgr =
	    ((struct tcp_context *)conn->tcp_layer->context)->socket_manager;
	notify_socket_readable_snd(mgr, conn, &tcp_conn_ops);
}

void client_init_tcp_connection(struct tcp_ipv4_conn *conn)
{
	uint32_t iss = generate_random_iss();
	conn->iss = iss;
	conn->snd_buffer.snd_nxt = iss;
	conn->snd_buffer.snd_una = iss;

	conn->ece_enabled = false;
	conn->wscale_enabled = true;
	conn->sack_enabled = true;
	conn->ts_enabled = true;

	conn->snd_mss = TCP_MSS_DEFAULT_FALLBACK;
	conn->snd_buffer.cwnd = TCP_INIT_CWND_MSS_MULT * conn->snd_mss;
	conn->rcv_buffer.rcv_wnd = calc_rcv_wnd_sws(conn);
}

// initialse seq/ack numbers and options connection based on incoming seg
// called on SYN receive (no cookies)
void server_init_tcp_connection(struct tcp_ipv4_conn *conn, struct tcp_segment *seg)
{
	uint32_t iss = generate_random_iss();
	conn->iss = iss;
	conn->irs = ntohl(seg->header->seq_num);
	conn->rcv_buffer.rcv_nxt = conn->irs + seg_seq_len(seg);
	conn->snd_buffer.snd_nxt = iss;
	conn->snd_buffer.snd_una = iss;
	conn->snd_buffer.snd_wndw = ntohs(seg->header->window);

	struct tcp_options *opt = seg->options;
	conn->sack_enabled = opt->sack_permitted;
	conn->ts_enabled = opt->ts_present;
	conn->wscale_enabled = opt->wscale_present;
	if (opt->mss_present) {
		uint16_t mss = opt->mss;
		conn->snd_mss = mss < TCP_MSS_DEFAULT_FALLBACK ? TCP_MSS_DEFAULT_FALLBACK : mss;
		conn->snd_mss -= (conn->ts_enabled ? TCP_OP_TS_LEN : 0);
	} else {
		conn->snd_mss = TCP_MSS_DEFAULT_FALLBACK;
	}
	conn->snd_buffer.cwnd = TCP_INIT_CWND_MSS_MULT * conn->snd_mss;

	if (opt->wscale_present)
		conn->snd_buffer.snd_wscale = opt->wscale;

	if (opt->ts_present)
		conn->ts_recent = opt->tsval;

	conn->rcv_buffer.rcv_wnd = calc_rcv_wnd_sws(conn);
}

void delayed_ack_callback(void *c)
{
	struct tcp_ipv4_conn *conn = (struct tcp_ipv4_conn *)c;
	pthread_mutex_lock(&conn->lock);
	if (conn->data_timers_cancelled) {
		pthread_mutex_unlock(&conn->lock);
		return;
	}
	pthread_mutex_unlock(&conn->lock);

	struct pkt *p = allocate_pkt();
	if (!p)
		return;
	tcp_fast_reply_pure_ack(p, conn);
}

// fast reply bypassing send buffer
pkt_result tcp_fast_reply_pure_ack(struct pkt *p, struct tcp_ipv4_conn *conn)
{
	printf("Fast reply pure ACK! \n \n");
	write_pkt_tcp_general_metadata(conn, p);
	p->tcp_flags = TCP_ACK;

	// set SACK
	if (conn->sack_enabled) {
		struct byte_reassembly_rcv_buffer *buff = &conn->rcv_buffer;
		lock_rcv_buff(buff);
		size_t count =
		    buff->ooo_count > TCP_HEADER_MAX_SACK ? TCP_HEADER_MAX_SACK : buff->ooo_count;
		p->tcp_options->sack_block_count = count;
		for (size_t i = 0; i < count; i++) {
			p->tcp_options->sacks[i] = buff->ooo_segs[i];
		}
		unlock_rcv_buff(buff);
	}

	p->len = sizeof(struct tcp_header_no_options) + calc_tcp_options_len(p->tcp_options);
	p->offset = PKT_SIZE - p->len;
	conn->ack_pending = false;
	struct tcp_context *ctx = (struct tcp_context *)conn->tcp_layer->context;
	struct timer_manager *tmgr = ctx->timer_mgr;
	cancel_timer(tmgr, conn->del_ack_timer);

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
	p->tcp_seq = conn->snd_buffer.retransmit ? conn->snd_buffer.snd_una
						 : conn->snd_buffer.snd_nxt;
	p->tcp_ack = conn->rcv_buffer.rcv_nxt;
	p->rcv_window = conn->rcv_buffer.rcv_wnd;
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
	bool can_accept = false;
	pthread_mutex_lock(&conn->lock);
	conn->state = state;
	pthread_mutex_unlock(&conn->lock);

	struct tcp_ipv4_listener *l = conn->lstnr;
	if (l && state == ESTABLISHED) {
		l->half_open_count--;
		push_q(l->ready_q, &conn->q_node, false);
	} else if (state == ESTABLISHED)
		can_accept = true;

	// don't cancel before our FIN got ACKd, might need to retransmit!
	if ((state == CLOSED || state == FIN_WAIT_2 || state == TIME_WAIT) &&
	    !conn->data_timers_cancelled) {

		struct timer_manager *tmgr =
		    ((struct tcp_context *)conn->tcp_layer->context)->timer_mgr;

		cancel_timer(tmgr, conn->rto_timer);
		cancel_timer(tmgr, conn->del_ack_timer);
		cancel_timer(tmgr, conn->zwp_timer);
		conn->data_timers_cancelled = true;
	}

	if (state == TIME_WAIT) {
		struct tcp_context *ctx = (struct tcp_context *)conn->tcp_layer->context;
		struct socket_manager *smgr = ctx->socket_manager;
		struct tcp_ipv4_conn_htable *time_wait_htable =
		    smgr->tcp_ipv4_conn_time_wait_htable;
		add_to_tcp_conn_hashtable(time_wait_htable, conn);
		remove_from_tcp_conn_hashtable(smgr->tcp_ipv4_conn_htable, conn);
		start_timer(ctx->timer_mgr, conn->time_wait_timer, TCP_TIMEWAIT_LEN);
	}

	// no more read nor write, need separate broadcasts for CLOSED incase of RST (not going
	// through standard closing states)
	if (state == CLOSED) {
		pthread_cond_broadcast(&conn->snd_buffer.cond);
		pthread_cond_broadcast(&conn->rcv_buffer.cond);
		pthread_cond_broadcast(&conn->estblshd_cond);
	}
	// no more read, can still write
	if (state == CLOSE_WAIT || state == TIME_WAIT || state == CLOSING)
		pthread_cond_broadcast(&conn->rcv_buffer.cond);
	// no more write, can still read
	if (state == FIN_WAIT_1)
		pthread_cond_broadcast(&conn->snd_buffer.cond);

	if (can_accept)
		pthread_cond_broadcast(&conn->estblshd_cond);
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
	if (conn->ref_count == 0)
		should_destroy = true;

	pthread_mutex_unlock(&(conn->lock));
	if (should_destroy)
		destroy_tcp_conn(conn);
}

// caller must hold lock!
void q_retain_tcp_conn(struct queue_node *n)
{
	struct tcp_ipv4_conn *conn = CONTAINER_OF(n, struct tcp_ipv4_conn, q_node);
	conn->ref_count++;
}

void q_release_tcp_conn(struct queue_node *n)
{
	struct tcp_ipv4_conn *conn = CONTAINER_OF(n, struct tcp_ipv4_conn, q_node);
	release_tcp_conn(conn);
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

bool tcp_is_snd_queued(void *s)
{
	return ((struct tcp_ipv4_conn *)s)->queued_for_snd;
}

// caller must hold lock!
void tcp_set_snd_queued(void *s, bool v)
{
	((struct tcp_ipv4_conn *)s)->queued_for_snd = v;
}

void destroy_tcp_conn(struct tcp_ipv4_conn *conn)
{
	printf("\n\nDESTROYING CONNECTION!! \n\n");
	struct tcp_context *ctx = (struct tcp_context *)conn->tcp_layer->context;
	struct timer_manager *tmgr = ctx->timer_mgr;

	pthread_mutex_lock(&conn->lock);
	destroy_byte_rcv_buffer(&conn->rcv_buffer);
	destroy_byte_snd_buffer(&conn->snd_buffer);
	cancel_timer(tmgr, conn->del_ack_timer);
	cancel_timer(tmgr, conn->rto_timer);
	cancel_timer(tmgr, conn->zwp_timer);
	cancel_timer(tmgr, conn->time_wait_timer);
	free(conn->del_ack_timer);
	free(conn->rto_timer);
	free(conn->zwp_timer);
	free(conn->time_wait_timer);
	pthread_cond_destroy(&conn->estblshd_cond);
	pthread_mutex_unlock(&conn->lock);
	pthread_mutex_destroy(&conn->lock);
	free(conn);
}

// caller must hold send buffer lock
struct pkt *create_tcp_packet(struct tcp_ipv4_conn *conn, size_t seq, size_t seq_len)
{
	// printf("\nCREATING PACKET\n");
	struct pkt *p = allocate_pkt();
	if (!p)
		return NULL;
	write_pkt_tcp_general_metadata(conn, p);

	size_t payload_len = seq_len;

	struct byte_snd_buffer *b = &conn->snd_buffer;
	for (uint8_t i = 0; i < b->ctrl_count; i++)
		if (tcp_seq_after_eq(b->ctrl[i].seq, seq) &&
		    tcp_seq_before(b->ctrl[i].seq, seq + seq_len)) {
			p->tcp_flags |= b->ctrl[i].flags;
			payload_len--;
		}

	if (conn->state != SYN_SENT)
		p->tcp_flags |= TCP_ACK;

	// add handshake options
	if (conn->state == SYN_SENT || conn->state == SYN_RECEIVED) {
		if (conn->wscale_enabled) {
			p->tcp_options->wscale_present = true;
			p->tcp_options->wscale = conn->rcv_buffer.rcv_wscale;
		}
		p->tcp_options->mss = conn->rcv_mss;
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
	size_t data_offset = PKT_SIZE - payload_len;
	read_from_snd_buff(&conn->snd_buffer, p->data + data_offset, payload_len);

	////////////////// DO THIS AFTER ATUALLY SENDING THE PACKET ?!!!//////////////
	struct byte_snd_buffer *sb = &conn->snd_buffer;
	if (sb->retransmit) {
		sb->retransmit = false;
	} else {
		sb->snd_nxt += seq_len;
		sb->snd_nxt_i = (sb->snd_nxt_i + payload_len) & (sb->capacity - 1);
	}
	// start timer if not running yet
	if (conn->rto_timer->node.index == NODE_NOT_IN_HEAP) {
		struct tcp_context *ctx = (struct tcp_context *)conn->tcp_layer->context;
		printf("starting RTO timer \n");
		start_timer(ctx->timer_mgr, conn->rto_timer, conn->rto);
	}
	///////////////////////////////////////////////////////

	// printf("\nRETURNING PACKET\n");

	return p;
}

struct pkt *tcp_try_get_pkt(void *s)
{
	// printf("TRY GET PACKET!!!! \n");
	struct tcp_ipv4_conn *conn = (struct tcp_ipv4_conn *)s;
	tcp_lock_conn(conn);
	if (!tcp_conn_alive(conn)) {
		tcp_unlock_conn(conn);
		return NULL;
	}
	tcp_unlock_conn(conn);

	struct byte_snd_buffer *buff = &conn->snd_buffer;
	struct pkt *p;

	lock_snd_buff(buff);
	uint32_t snd_seq = !buff->retransmit ? buff->snd_nxt : buff->snd_una;
	uint32_t window = conn->state == SYN_SENT ? 1 : usable_window(conn);
	printf("WINDOW = %d \n", window);
	if (window == 0) {
		unlock_snd_buff(buff);
		return NULL;
	}

	uint32_t tail_seq = buff->snd_una + (uint32_t)buff->used_bytes + buff->ctrl_count;
	uint32_t bytes_ready = tail_seq - snd_seq;

	// printf("snd_una: %u, used_bytes: %d, ctrl_count: %u \n",
	//        buff->snd_una,
	//       (uint32_t)buff->used_bytes,
	//        buff->ctrl_count);
	// printf("BYTES READY = %u \n", bytes_ready);

	if (bytes_ready == 0) {
		unlock_snd_buff(buff);
		return NULL;
	}
	printf("BYTES READY: %d \n", bytes_ready);
	// in general we want to send MSS
	uint32_t min_bytes_snd = conn->snd_mss;

	// unless a SYN/FIN is coming up, then we just want to be able to send the amount of
	// bytes it takes to reach the control seq
	if (buff->ctrl_count > 0 && tcp_seq_after_eq(buff->ctrl[0].seq, snd_seq)) {
		uint32_t len_to_reach_ctrl = (buff->ctrl[0].seq - snd_seq) + 1;
		if (window >= len_to_reach_ctrl && conn->snd_mss > len_to_reach_ctrl) {
			p = create_tcp_packet(conn, snd_seq, len_to_reach_ctrl);
			unlock_snd_buff(buff);
			return p;
		}
	}
	printf("MIN BYTES SEND: %d \n", min_bytes_snd);

	if (buff->retransmit) {
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
	printf("WINDOW: %u \n", window);
	if (window < min_bytes_snd || min_bytes_snd < 1) {
		unlock_snd_buff(buff);
		return NULL;
	}

	printf("CREATING PKT SEQ: %u, LEN: %d \n", snd_seq, min_bytes_snd);
	p = create_tcp_packet(conn, snd_seq, min_bytes_snd);
	unlock_snd_buff(buff);
	return p;
}

pkt_result tcp_send_packet(struct stack *stack, struct pkt *p)
{
	pkt_result r = stack->tcp_layer->send_down(stack->tcp_layer, p);

	// edit rcv_next, start timers, etc?
	return r;
}

void tcp_end_snd(struct stack *stack, void *sock)
{
	struct tcp_ipv4_conn *conn = (struct tcp_ipv4_conn *)sock;
	struct byte_snd_buffer *buff = &conn->snd_buffer;
	lock_snd_buff(buff);
	sndbuf_insert_ghost_byte(buff, TCP_FIN);
	unlock_snd_buff(buff);
	notify_socket_readable_snd(stack->sock_manager, sock, &tcp_conn_ops);

	// SHOULD ONLY TRANSITION AFTER FIN IS ACTUALLY SENT OUT??
	if (conn->state == ESTABLISHED)
		tcp_transition_to_state(conn, FIN_WAIT_1);
	else if (conn->state == CLOSE_WAIT)
		tcp_transition_to_state(conn, LAST_ACK);
}

void tcp_close_conn(struct stack *stack, void *sock)
{
	struct tcp_ipv4_conn *conn = (struct tcp_ipv4_conn *)sock;
	if (conn->state == ESTABLISHED || conn->state == CLOSE_WAIT)
		tcp_end_snd(stack, sock);
}

ssize_t tcp_write_to_snd_buff(struct stack *stack, void *sock, struct send_request *req)
{
	if (!stack || !sock || !req->data || req->len < 1)
		return -1;

	struct tcp_ipv4_conn *conn = (struct tcp_ipv4_conn *)sock;
	ssize_t r = blocking_write_to_snd_buff(&conn->snd_buffer, req->data, req->len, conn);
	if (r > 0)
		notify_socket_readable_snd(stack->sock_manager, sock, &tcp_conn_ops);
	return r;
}

ssize_t tcp_read_from_rcv_buff(void *sock, size_t len, unsigned char *buff)
{
	if (!sock || len < 1 || !buff)
		return -1;
	printf("START READING FROM RCV_BUFF!!! \n\n");
	struct tcp_ipv4_conn *conn = (struct tcp_ipv4_conn *)sock;
	struct byte_reassembly_rcv_buffer *b = &conn->rcv_buffer;

	lock_rcv_buff(b);
	bool prev_low_wndw = b->rcv_wnd < TCP_MSS_DEFAULT_FALLBACK;
	ssize_t r = blocking_read_from_rcv_buff(&conn->rcv_buffer, buff, len);
	printf("READ %ld BYTES FROM BUFFER!\n\n", r);
	b->rcv_wnd = calc_rcv_wnd_sws(conn);
	bool curr_low_wnwd = b->rcv_wnd < TCP_MSS_DEFAULT_FALLBACK;
	unlock_rcv_buff(b);

	if (prev_low_wndw && !curr_low_wnwd) {
		printf("SEND WINDOW UPDATE!! NEW WINDOW: %u \n", b->rcv_wnd);
		struct pkt *p = allocate_pkt();
		if (p)
			tcp_fast_reply_pure_ack(p, conn); // SEND WINDOW UPDATE!
	}
	return r;
}