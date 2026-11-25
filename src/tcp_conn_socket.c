#include "tcp_conn_socket.h"
#include "buffer_pool.h"
#include "container_of.h"
#include "ethernet.h"
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
#include "time_now.h"
#include "timer.h"
#include "window_helpers.h"
#include <arpa/inet.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>

// one full-sized segment plus the IPv4 and Ethernet headers added below TCP must fit in a pkt
// buffer
_Static_assert(TCP_MSS_MAX + sizeof(struct tcp_header_no_options) + sizeof(struct ipv4_header)
		       + sizeof(struct ethernet_header)
		   <= PKT_SIZE,
	       "TCP_MSS_MAX does not fit in a packet buffer");
_Static_assert(TCP_MIN_SND_MSS > TCP_OP_TS_LEN, "TCP_MIN_SND_MSS must leave room for payload");

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

static inline bool tcp_state_accepts_data(tcp_connection_state s)
{
	return s == ESTABLISHED || s == FIN_WAIT_1 || s == FIN_WAIT_2;
}

// marks the connection aborted and wakes every blocked reader and writer.
// each broadcast is made while holding conn->lock => a waiter checks aborted flag under
// same lock and keeps holding it until pthread_cond_wait() releases it, so it either
// sees the flag, or is already waiting when the broadcast arrives => no wakeup can be lost.
static void tcp_flag_conn_aborted(struct tcp_ipv4_conn *conn)
{
	conn->aborted = true;

	pthread_cond_broadcast(&conn->snd_buffer.cond);
	pthread_cond_broadcast(&conn->rcv_buffer.cond);
}

void abort_tcp_conn(struct tcp_ipv4_conn *conn)
{
	struct tcp_deferred_work d = {0};
	pthread_mutex_lock(&conn->lock);
	tcp_flag_conn_aborted(conn);
	tcp_set_state_locked(conn, CLOSED, &d);
	pthread_mutex_unlock(&conn->lock);
	tcp_execute_deffered_work(conn, &d);
}

// Resends our SYN / SYN-ACK right away, without going through the RTO: no backoff,
// no cwnd collapse, and it doesn't count as a timeout.
static void tcp_resend_syn_deferred(struct tcp_ipv4_conn *conn, struct tcp_deferred_work *d)
{
	struct byte_snd_buffer *sb = &conn->snd_buffer;
	sb->retransmit = true; // retransmitting from snd_una = the SYN
	d->notify_TX_snd = true;
}

// never use for TIME_WAIT TIMER
static bool tcp_arm_data_timer(struct tcp_ipv4_conn *conn, struct timer *t, uint64_t delay_ms)
{
	if (conn->data_timers_cancelled)
		return false;
	struct timer_manager *t_mgr = ((struct tcp_context *)conn->tcp_layer->context)->timer_mgr;
	return start_timer(t_mgr, t, delay_ms);
}

// never use for TIME_WAIT TIMER
static bool arm_tcp_data_timer_if_idle(struct tcp_ipv4_conn *conn,
				       struct timer *t,
				       uint64_t delay_ms)
{
	if (conn->data_timers_cancelled)
		return false;
	struct timer_manager *t_mgr = ((struct tcp_context *)conn->tcp_layer->context)->timer_mgr;
	return start_timer_if_idle(t_mgr, t, delay_ms);
}

static void tcp_negotiate_wscale(struct tcp_ipv4_conn *conn, const struct tcp_options *opt)
{
	if (conn->wscale_enabled && opt->wscale_present) {
		conn->snd_buffer.snd_wscale = opt->wscale; // already clamped to 14 by the parser
	} else {
		conn->wscale_enabled = false;
		conn->snd_buffer.snd_wscale = 0;
		conn->rcv_buffer.rcv_wscale = 0;
	}
}

static bool tcp_seg_acceptable(uint32_t seq, uint32_t len, uint32_t rcv_nxt, uint32_t wnd)
{
	if (len == 0)
		return wnd == 0
			   ? seq == rcv_nxt
			   : tcp_seq_after_eq(seq, rcv_nxt) && tcp_seq_before(seq, rcv_nxt + wnd);
	if (wnd == 0)
		return false;
	uint32_t end = seq + len - 1;
	return (tcp_seq_after_eq(seq, rcv_nxt) && tcp_seq_before(seq, rcv_nxt + wnd))
	       || (tcp_seq_after_eq(end, rcv_nxt) && tcp_seq_before(end, rcv_nxt + wnd));
}

static pkt_result tcp_process_ack(struct pkt *p,
				  struct tcp_segment *seg,
				  struct tcp_ipv4_conn *conn,
				  struct tcp_deferred_work *out_d,
				  bool count_dupacks)
{
	uint32_t seg_ack = ntohl(seg->header->ack_num);
	uint16_t flags = seg->header->flags;
	uint32_t snd_next = conn->snd_buffer.snd_nxt;
	uint32_t snd_una = conn->snd_buffer.snd_una;
	size_t s_len = seg_seq_len(seg);
	struct tcp_context *ctx = (struct tcp_context *)conn->tcp_layer->context;
	struct timer_manager *tmgr = ctx->timer_mgr;

	bool valid_new_ack = tcp_seq_after(seg_ack, snd_una)
			     && tcp_seq_before_eq(seg_ack, snd_next);
	bool dupe_ack = (seg_ack == snd_una);

	if (valid_new_ack || dupe_ack) {
		struct byte_snd_buffer *sb = &conn->snd_buffer;
		uint32_t prev_peer_wnd = sb->snd_wnd;
		sb->snd_wnd = tcp_seg_wnd_bytes(seg, sb->snd_wscale);

		// peer is alive: any ACK answers our window probes
		// new data acked means our retransmissions got through
		conn->zwp_unanswered = 0;
		if (valid_new_ack)
			conn->rto_timeouts = 0;

		bool window_update = conn->is_wndw_probing && sb->snd_wnd > prev_peer_wnd;

		switch (conn->state) {
		case SYN_SENT:
			if (valid_new_ack && (seg_ack == conn->iss + 1)) {
				conn->snd_buffer.snd_una = seg_ack;
				conn->snd_buffer.ctrl_count--;
				if (flags & TCP_SYN)
					tcp_set_state_locked(conn, ESTABLISHED, out_d);
			}
			break;

		case SYN_RECEIVED:
			if (valid_new_ack) {
				// if ready q full drop whole segment and stay in
				// SYN_RECEIVED try again after SYN-ACK retransmission's new
				// ACK reply
				if (conn->lstnr && q_full(conn->lstnr->ready_q))
					return TCP_LSTNR_READY_Q_FULL;
				tcp_set_state_locked(conn, ESTABLISHED, out_d);
				conn->snd_buffer.snd_una = seg_ack;
				conn->snd_buffer.ctrl_count--;
			}
			break;

		default:
			if (valid_new_ack) {
				uint32_t old_una = sb->snd_una;
				uint32_t data_ackd = seg_ack - old_una;

				// is our FIN acked? Decided from the FIN entry itself,
				// never from the state, so the byte accounting is right in
				// any state
				bool fin_acked = false;
				for (uint8_t i = 0; i < sb->ctrl_count; i++) {
					if (sb->ctrl[i].flags == TCP_FIN
					    && tcp_seq_after(seg_ack, sb->ctrl[i].seq)) {
						fin_acked = true;
						data_ackd--;
						assert(i == sb->ctrl_count - 1);
						sb->ctrl_count--;
						break;
					}
				}
				// update snd_una and head
				update_snd_nxt_head(sb, seg_ack, data_ackd);

				if (fin_acked) {
					switch (conn->state) {
					case FIN_WAIT_1: // waiting for the peer's FIN
						tcp_set_state_locked(conn, FIN_WAIT_2, out_d);
						break;
					case CLOSING: // both FINs sent and acked
						tcp_set_state_locked(conn, TIME_WAIT, out_d);
						break;
					case LAST_ACK: // peer's FIN came first, we're done
						tcp_set_state_locked(conn, CLOSED, out_d);
						break;
					default: // unreachable: tcp_end_snd changes state
						 // before sending out FIN
						break;
					}
				}

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
					size_t overtaken_sacks = bin_search_seq_after_eq_indx(
					    sb->snd_una, sb->sack_blocks, sb->sack_blocks_count);

					if (overtaken_sacks < sb->sack_blocks_count
					    && sb->sack_blocks[overtaken_sacks].start_seq
						   == sb->snd_una)
						overtaken_sacks++;

					if (overtaken_sacks > 0) {
						memmove(&sb->sack_blocks,
							&sb->sack_blocks[overtaken_sacks],
							(sb->sack_blocks_count - overtaken_sacks)
							    * sizeof(struct ooo_seg));
						sb->sack_blocks_count -= overtaken_sacks;
					}
				}

				// pure dupe ack, no data, disregard window probe replies
			} else if (count_dupacks && s_len == 0 && !conn->is_wndw_probing
				   && sb->snd_una != sb->snd_nxt && // data outstanding
				   sb->snd_wnd == prev_peer_wnd) { // window unchanged (RFC 5681, 2)
				switch (sb->c_state) {
				case FAST_RECOVERY:
					sb->cwnd += conn->snd_mss;
					break;
				default:
					conn->dup_ack_cnt++;
					if (conn->dup_ack_cnt == 3)
						fast_recovery(conn, out_d);
					break;
				}
			}

			// process new sack blocks
			size_t sack_count = seg->options->sack_block_count;
			struct ooo_seg *sacks = seg->options->sacks;
			for (size_t i = 0; i < sack_count; i++) {
				uint32_t s_start = sacks[i].start_seq;
				uint32_t s_end = sacks[i].end_seq;

				if (should_store_sack_block(sb, s_start, s_end, sb->snd_una)) {
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

		if (valid_new_ack) {
			// retransmission timer
			cancel_timer(tmgr, conn->rto_timer);
			conn->rto_interval = TCP_INIT_RTO_MS;
			if (sb->snd_nxt != sb->snd_una) {
				tcp_arm_data_timer(conn, conn->rto_timer, conn->rto_interval);
			}
			// notify send buffer we can overwrite acked data
			pthread_cond_broadcast(&sb->cond);
			// add socket to tx queue to send out potential new packets
			out_d->notify_TX_snd = true;
		} else if (conn->is_wndw_probing
			   && window_update) { // don't stop window probing yet, sender might
					       // suffer from silly-window syndrome
			out_d->notify_TX_snd = true;
		}

	} else if (tcp_seq_after(seg_ack, snd_next)) {
		// ACK out of sync, send challenge ACK
		tcp_create_ack_reply(p, conn, out_d);
		return TCP_ACK_OUT_OF_SYNC;
	}
	return TCP_ACK_PROCESSED;
}

// caller must hold conn->lock execute deferred work after unlocking
pkt_result process_tcp_segment(struct pkt *p,
			       struct tcp_segment *seg,
			       struct tcp_ipv4_conn *conn,
			       struct tcp_deferred_work *out_d)
{
	uint32_t seg_seq = ntohl(seg->header->seq_num);
	uint32_t seg_ack = ntohl(seg->header->ack_num);
	uint16_t flags = seg->header->flags;

	uint32_t snd_next = conn->snd_buffer.snd_nxt;
	uint32_t rcv_next = conn->rcv_buffer.rcv_nxt;
	uint32_t scaled_rcv_wnd = conn->rcv_buffer.rcv_wnd << conn->rcv_buffer.rcv_wscale;

	size_t s_len = seg_seq_len(seg);

	struct tcp_context *ctx = (struct tcp_context *)conn->tcp_layer->context;
	struct timer_manager *tmgr = ctx->timer_mgr;

	if (conn->state != SYN_SENT
	    && !tcp_seg_acceptable(seg_seq, s_len, rcv_next, scaled_rcv_wnd)) {
		if (flags & TCP_RST)
			return TCP_SEG_OUT_OF_WNDW_RANGE; // drop, never reply to an RST

		if (s_len > 0 && (flags & TCP_SYN) && !(flags & TCP_ACK)
		    && conn->state == SYN_RECEIVED
		    && seg_seq == conn->irs) { // duplicate SYN: retrigger SYN-ACK sending
			tcp_resend_syn_deferred(conn, out_d);
			return RCOV_SYN_ACK_TO_SND_BUFFER;
		}

		if (scaled_rcv_wnd == 0 && (flags & TCP_ACK)) {
			bool count_dupacks = tcp_seq_after_eq(
			    seg_seq,
			    rcv_next); // don't count window probes or keepalives as dupeacks
			pkt_result ack_r = tcp_process_ack(
			    p, seg, conn, out_d, count_dupacks); // process the ACK, drop the data
			if (ack_r != TCP_ACK_PROCESSED)
				return ack_r;
		}

		// our previous ACK lost, restart timer
		if (conn->state == TIME_WAIT && flags & TCP_FIN)
			start_timer(tmgr, conn->time_wait_timer, TCP_TIMEWAIT_MS);

		// rare case where final ACK to close connection arrived while we had zero window
		// OR connection was already marked closed but deferred unhashing didn't happen yet
		// => no ACK should go out
		if (!tcp_conn_alive(conn))
			return TCP_SEG_OUT_OF_WNDW_RANGE;

		// rate limit ACKS sent on unacceptable segments, prevents attacker spam resulting
		// in high traffic & ACK loops on desyncd peers.
		// exemptions: zero-window probe
		// replies and TIME_WAIT FIN replies, the peer relies on them
		bool exempt = scaled_rcv_wnd == 0
			      || (conn->state == TIME_WAIT && (flags & TCP_FIN));
		uint64_t now = now_ms();
		if (exempt || now - conn->last_oow_ack_ms >= TCP_OOW_ACK_RATELIMIT_MS) {
			tcp_create_ack_reply(p, conn, out_d); // ACK every rejected segment (except
							      // RST)
			conn->last_oow_ack_ms = now;
			return TCP_SEG_OUT_WNDW_RNG_ACK_SNT;
		}
		return TCP_SEG_OUT_OF_WNDW_RANGE;
	}

	// RST processing
	if (flags & TCP_RST) {
		if (seg_seq == rcv_next) {
			out_d->abort = true;
			return INC_RST_CONN_DEAD;
		}
		// per RFC 5961
		if (conn->state != SYN_SENT) {
			tcp_create_ack_reply(p, conn, out_d);
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
			conn->ts_enabled = seg->options->ts_present;
			conn->sack_enabled = seg->options->sack_permitted;
			conn->snd_mss = tcp_effective_snd_mss(seg->options->mss_present,
							      seg->options->mss,
							      conn->rcv_mss,
							      conn->ts_enabled);
			conn->snd_buffer.cwnd = TCP_INIT_CWND_MSS_MULT * conn->snd_mss;
			tcp_negotiate_wscale(conn, seg->options);
			conn->rcv_buffer.rcv_wnd = calc_rcv_wnd_sws(conn);

			if (!(flags & TCP_ACK)) {
				// simultaneous open: received SYN while expecting SYN-ACK
				// trigger SYN-retransmission, SYN_RECEIVED state will
				// append ACK
				tcp_set_state_locked(conn, SYN_RECEIVED, out_d);
				tcp_resend_syn_deferred(conn, out_d);
				return TCP_SIMULTANEOUS_OPEN;
			}
			// else (SYN-ACK) => fallthrough to ACK processing below to finalise
			// handshake

		} else if (conn->state >= ESTABLISHED) {
			// unexpected SYN in established session
			tcp_build_rst_reply(p, seg);
			out_d->pkt_snd_now = p;
			out_d->abort = true;
			return RST_UNEXPECTED_SYN;
		}
	}

	if (flags & TCP_ACK) {
		pkt_result ack_r = tcp_process_ack(p, seg, conn, out_d, true);
		if (ack_r != TCP_ACK_PROCESSED)
			return ack_r;
	}

	// data handling: trimming is done by rcv_buffer_write_tcp_segment
	if (tcp_state_accepts_data(conn->state) && seg->payload_len > 0) {
		rcv_buffer_write_tcp_segment(&conn->rcv_buffer, seg, &immediate_ack);
		conn->rcv_buffer.rcv_wnd = calc_rcv_wnd_sws(conn);
		// delayed ACK logic: 1st packet starts timer, 2nd packet triggers immediate
		// ACK
		if (!immediate_ack && !conn->ack_pending) {
			conn->ack_pending = true;
			if (!tcp_arm_data_timer(conn, conn->del_ack_timer, TCP_DEL_ACK_MS)) {
				conn->ack_pending = false;
				immediate_ack =
				    true; // if setting ACK timer fails, send immediate ack
			}
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
		rcv_buff_accept_fin(&conn->rcv_buffer);
		immediate_ack = true;
		if (conn->state == ESTABLISHED)
			tcp_set_state_locked(conn, CLOSE_WAIT, out_d);
		else if (conn->state == FIN_WAIT_1) {
			bool fin_acked = (flags & TCP_ACK)
					 && (seg_ack == snd_next); // no more data after FIN, so
								   // snd_next is FIN's seq + 1
			tcp_set_state_locked(conn, fin_acked ? TIME_WAIT : CLOSING, out_d);

		} else if (conn->state == FIN_WAIT_2) {
			tcp_set_state_locked(conn, TIME_WAIT, out_d);
		}
	}
	if (immediate_ack) {
		tcp_create_ack_reply(p, conn, out_d);
		return TCP_IMMEDIATE_ACK_SNT;
	}
	return TCP_SEG_PROCESSED;
}

// enqueues the tcp connection sock to TX worker queue
// after dequeing actual ops.send_packet will check state and append ACK if needed
void tcp_syn_to_snd_buff_deferred(struct tcp_ipv4_conn *conn, struct tcp_deferred_work *d)
{
	sndbuf_insert_ghost_byte(&conn->snd_buffer, TCP_SYN);
	d->notify_TX_snd = true;
}

// enqueues the tcp connection sock to TX worker queue
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

// effective send MSS: the peer's MSS (536 if it sent none), never above our own rcv_mss,
// never below TCP_MIN_SND_MSS, minus the timestamp option that every segment then carries
uint32_t tcp_effective_snd_mss(bool peer_mss_present,
			       uint16_t peer_mss,
			       uint32_t rcv_mss,
			       bool ts_enabled)
{
	uint32_t mss = peer_mss_present ? peer_mss : TCP_MSS_DEFAULT_FALLBACK;
	if (mss > rcv_mss)
		mss = rcv_mss;
	if (mss < TCP_MIN_SND_MSS)
		mss = TCP_MIN_SND_MSS;
	return ts_enabled ? mss - TCP_OP_TS_LEN : mss;
}

// MSS we advertise and can receive: what the route's MTU allows, capped to what fits in one
// packet buffer. route may be NULL (no route known), which gives the 536 default.
uint32_t tcp_calc_rcv_mss(const struct route *route)
{
	const uint32_t hdrs = sizeof(struct ipv4_header) + sizeof(struct tcp_header_no_options);
	uint32_t mss = TCP_MSS_DEFAULT_FALLBACK;
	if (route && route->mtu > hdrs + TCP_MIN_SND_MSS)
		mss = route->mtu - hdrs;
	return mss > TCP_MSS_MAX ? TCP_MSS_MAX : mss;
}

// create connection for id, init general values
struct tcp_ipv4_conn *create_init_tcp_connection(struct tcp_conn_id *id,
						 struct nw_layer *tcp,
						 struct route *route)
{
	// every field zeroed, nothing left uninitialised by accident
	struct tcp_ipv4_conn *conn = calloc(1, sizeof(*conn));
	if (!conn)
		return NULL;

	if (pthread_mutex_init(&conn->lock, NULL) != 0)
		goto err_free_conn;
	if (pthread_cond_init(&conn->estblshd_cond, NULL) != 0)
		goto err_destroy_lock;

	if (init_byte_snd_buffer(&conn->snd_buffer, TCP_DEFAULT_BUFFER_SIZE) < 0)
		goto err_destroy_cond;
	if (init_byte_rcv_buffer(&conn->rcv_buffer, TCP_DEFAULT_BUFFER_SIZE) < 0)
		goto err_destroy_snd_buffer;

	conn->del_ack_timer = create_timer_owned(
	    delayed_ack_callback, conn, tcp_retain_conn, tcp_release_conn);
	conn->rto_timer = create_timer_owned(rto_callback, conn, tcp_retain_conn, tcp_release_conn);
	conn->zwp_timer = create_timer_owned(zwp_callback, conn, tcp_retain_conn, tcp_release_conn);
	conn->time_wait_timer = create_timer_owned(
	    time_wait_callback, conn, tcp_retain_conn, tcp_release_conn);
	if (!conn->del_ack_timer || !conn->rto_timer || !conn->zwp_timer || !conn->time_wait_timer)
		goto err_free_timers;

	atomic_init(&conn->ref_count, 0);
	conn->data_timers_cancelled = false;
	conn->aborted = false;

	conn->local_port = id->loc_port;
	conn->extern_port = id->extern_port;
	memcpy(conn->local_addr, id->loc_addr, IPV4_ADDR_LEN);
	memcpy(conn->extern_addr, id->extern_addr, IPV4_ADDR_LEN);

	// 0 used as "previous" value to calculate increase for current
	conn->rcv_buffer.rcv_wnd = 0;
	conn->rcv_buffer.rcv_wscale = tcp_calc_wndw_scale(TCP_DEFAULT_BUFFER_SIZE);

	conn->is_wndw_probing = false;
	conn->rto_interval = TCP_INIT_RTO_MS;
	conn->rto_timeouts = 0;
	conn->zwp_unanswered = 0;
	conn->ack_pending = false;
	conn->last_oow_ack_ms = 0;
	conn->in_order_full_seg_count = 0;
	conn->tcp_layer = tcp;
	conn->lstnr = NULL;
	conn->snd_buffer.snd_wscale = 0;
	conn->snd_buffer.snd_wnd = 0;
	conn->queued_for_snd = false;

	conn->q_node.nxt = Q_NODE_UNLINKED;

	conn->route = route;
	conn->rcv_mss = tcp_calc_rcv_mss(conn->route);
	return conn;

	// unwind in reverse order of construction; never armed, so plain free is safe
err_free_timers:
	free(conn->del_ack_timer); // free(NULL) is a no-op
	free(conn->rto_timer);
	free(conn->zwp_timer);
	free(conn->time_wait_timer);
	destroy_byte_rcv_buffer(&conn->rcv_buffer);
err_destroy_snd_buffer:
	destroy_byte_snd_buffer(&conn->snd_buffer);
err_destroy_cond:
	pthread_cond_destroy(&conn->estblshd_cond);
err_destroy_lock:
	pthread_mutex_destroy(&conn->lock);
err_free_conn:
	free(conn);
	return NULL;
}

void zwp_callback(void *c)
{
	struct tcp_ipv4_conn *conn = (struct tcp_ipv4_conn *)c;
	struct tcp_context *cntx = conn->tcp_layer->context;
	struct timer_manager *mngr = cntx->timer_mgr;

	struct byte_snd_buffer *sb = &conn->snd_buffer;

	struct tcp_deferred_work d = {0};
	pthread_mutex_lock(&conn->lock);

	if (!timer_should_execute(mngr, conn->zwp_timer) || conn->data_timers_cancelled
	    || !conn->is_wndw_probing) {
		pthread_mutex_unlock(&conn->lock);
		return;
	}

	// live peer ACKs every probe even with zero window (process_tcp_segment resets the count)
	if (conn->zwp_unanswered >= TCP_ZWP_UNANSWERED_MAX) {
		d.abort = true;
		pthread_mutex_unlock(&conn->lock);
		tcp_execute_deffered_work(conn, &d);
		return;
	}
	conn->zwp_unanswered++;

	uint32_t probe_seq = sb->snd_una - 1;

	// keep probing until windows opens (stop_wndw_probing will get called)
	conn->zwp_interval *= 2;
	if (conn->zwp_interval > TCP_MAX_ZWP_MS)
		conn->zwp_interval = TCP_MAX_ZWP_MS;
	tcp_arm_data_timer(conn, conn->zwp_timer, conn->zwp_interval);

	struct pkt *p = allocate_pkt();
	if (!p) {
		conn->zwp_unanswered--; // probe not being sent out, shouldn't count toward max
					// attempts
		pthread_mutex_unlock(&conn->lock);
		return;
	}

	write_pkt_tcp_general_metadata(conn, p);
	p->tcp_flags = TCP_ACK;
	p->tcp_seq = probe_seq;

	size_t data_offset = PKT_SIZE - 1;
	p->data[data_offset] = 0; // dummy probe byte

	p->len = sizeof(struct tcp_header_no_options) + calc_tcp_options_len(p->tcp_options) + 1;
	p->offset = PKT_SIZE - p->len;

	d.pkt_snd_now = p;
	pthread_mutex_unlock(&conn->lock);
	tcp_execute_deffered_work(conn, &d);
}

void rto_callback(void *c)
{
	struct tcp_ipv4_conn *conn = (struct tcp_ipv4_conn *)c;
	struct tcp_context *cntx = (struct tcp_context *)conn->tcp_layer->context;
	struct timer_manager *mngr = cntx->timer_mgr;
	struct byte_snd_buffer *sb = &conn->snd_buffer;
	struct tcp_deferred_work d = {0};
	pthread_mutex_lock(&conn->lock);

	// cancel_timer can't stop a callback that was already popped + an ACK may have
	// acknowledged everything between the pop and now => no data outstanding = stale RTO.
	if (!timer_should_execute(mngr, conn->rto_timer) || conn->data_timers_cancelled) {
		pthread_mutex_unlock(&conn->lock);
		return;
	}

	assert(sb->snd_una != sb->snd_nxt);

	conn->dup_ack_cnt = 0;
	bool handshake = conn->state == SYN_SENT || conn->state == SYN_RECEIVED;

	// zero window isn't a failure: the peer is alive and ACKs
	if (!conn->is_wndw_probing) {
		uint8_t limit = handshake ? TCP_SYN_TIMEOUTS_MAX : TCP_DATA_TIMEOUTS_MAX;
		if (++conn->rto_timeouts >= limit) {
			d.abort = true; // peer gone: give up (RFC 9293, 3.8.3)
			pthread_mutex_unlock(&conn->lock);
			tcp_execute_deffered_work(conn, &d);
			return;
		}
	}
	sb->c_state = SLOW_START;
	sb->cwnd = conn->snd_mss;
	sb->retransmit = true;
	conn->rto_interval *= 2;
	if (conn->rto_interval > TCP_MAX_RTO_MS)
		conn->rto_interval = TCP_MAX_RTO_MS;

	// re-arm here, not only in TX path: the next timeout must happen even if this
	// retransmission can't be built (packet pool empty, window closed, ...).
	tcp_arm_data_timer(conn, conn->rto_timer, conn->rto_interval);

	d.notify_TX_snd = true;
	pthread_mutex_unlock(&conn->lock);
	tcp_execute_deffered_work(conn, &d);
}

void time_wait_callback(void *c)
{
	struct tcp_ipv4_conn *conn = c;
	struct tcp_context *cntx = conn->tcp_layer->context;
	struct timer_manager *mgr = cntx->timer_mgr;
	struct tcp_deferred_work d = {0};
	pthread_mutex_lock(&conn->lock);
	bool current = timer_should_execute(mgr, conn->time_wait_timer) && conn->state == TIME_WAIT;
	if (current)
		tcp_set_state_locked(conn, CLOSED, &d);
	pthread_mutex_unlock(&conn->lock);
	if (current)
		tcp_execute_deffered_work(conn, &d);
}

void fast_recovery(struct tcp_ipv4_conn *conn, struct tcp_deferred_work *d)
{
	printf("\n\n            FAST RETRANSMIT! \n \n");

	struct byte_snd_buffer *sb = &conn->snd_buffer;
	sb->c_state = FAST_RECOVERY;
	sb->ssthresh = sb->cwnd / 2 > 2 * conn->snd_mss ? sb->cwnd / 2 : 2 * conn->snd_mss;
	sb->cwnd = sb->ssthresh + 3 * conn->snd_mss;

	sb->retransmit = true;
	d->notify_TX_snd = true;
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
	conn->snd_buffer.snd_wnd = tcp_seg_wnd_bytes(seg, 0); // don't apply scale for a SYN

	struct tcp_options *opt = seg->options;
	conn->sack_enabled = opt->sack_permitted;
	conn->ts_enabled = opt->ts_present;
	conn->snd_mss = tcp_effective_snd_mss(
	    opt->mss_present, opt->mss, conn->rcv_mss, conn->ts_enabled);
	conn->snd_buffer.cwnd = TCP_INIT_CWND_MSS_MULT * conn->snd_mss;
	conn->wscale_enabled = true; // enable scaling if peer allows it
	tcp_negotiate_wscale(conn, seg->options);

	if (opt->ts_present)
		conn->ts_recent = opt->tsval;

	conn->rcv_buffer.rcv_wnd = calc_rcv_wnd_sws(conn);
}

void delayed_ack_callback(void *c)
{
	struct tcp_ipv4_conn *conn = (struct tcp_ipv4_conn *)c;
	struct tcp_context *cntx = (struct tcp_context *)conn->tcp_layer->context;
	struct timer_manager *mngr = cntx->timer_mgr;
	struct tcp_deferred_work d = {0};
	pthread_mutex_lock(&conn->lock);

	if (!timer_should_execute(mngr, conn->del_ack_timer) || conn->data_timers_cancelled) {
		pthread_mutex_unlock(&conn->lock);
		return;
	}

	assert(conn->ack_pending);

	struct pkt *p = allocate_pkt();
	if (!p) {
		// ack still owed: try again shortly, keep ack_pending set
		tcp_arm_data_timer(conn, conn->del_ack_timer, TCP_DEL_ACK_MS);
		pthread_mutex_unlock(&conn->lock);
		return;
	}
	tcp_create_ack_reply(p, conn, &d); // retains pkt for d->snd_pkt_now
	pthread_mutex_unlock(&conn->lock);
	release_pkt(p); // release allocation ref
	tcp_execute_deffered_work(conn, &d);
}

// create ack reply and notify deferred work to immediate send out
void tcp_create_ack_reply(struct pkt *p, struct tcp_ipv4_conn *conn, struct tcp_deferred_work *d)
{
	printf("Fast reply pure ACK! \n \n");
	write_pkt_tcp_general_metadata(conn, p);
	p->tcp_flags = TCP_ACK;

	// set SACK
	if (conn->sack_enabled) {
		struct byte_reassembly_rcv_buffer *buff = &conn->rcv_buffer;
		size_t max = conn->ts_enabled ? TCP_HEADER_MAX_SACK_WITH_TS : TCP_HEADER_MAX_SACK;
		p->tcp_options->sack_block_count = rcv_buff_choose_sack_blocks(
		    buff, p->tcp_options->sacks, max);
	}

	p->len = sizeof(struct tcp_header_no_options) + calc_tcp_options_len(p->tcp_options);
	p->offset = PKT_SIZE - p->len;
	conn->ack_pending = false;
	struct tcp_context *ctx = (struct tcp_context *)conn->tcp_layer->context;
	struct timer_manager *tmgr = ctx->timer_mgr;
	cancel_timer(tmgr, conn->del_ack_timer);
	d->pkt_snd_now = p;
	retain_pkt(p); // d->pkt_snd_now's reference, released upon execution
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
	p->tcp_options->mss_present = false;
	p->tcp_options->sack_permitted = false;
	p->tcp_options->wscale_present = false;
	// no sack blocks
	p->tcp_options->sack_block_count = 0;
}

// sets new state and wake waiters, hand a passively opened connection to its listener.
// other work that takes lock itself or may drop references is recorded in fx
// several transitions in one critical section accumulate their effects in the same fx.
// caller must hold conn->lock
void tcp_set_state_locked(struct tcp_ipv4_conn *conn,
			  tcp_connection_state state,
			  struct tcp_deferred_work *d)
{
	tcp_connection_state old = conn->state;
	conn->state = state;

	// passively opened connection stops being half-open as soon as it leaves
	// SYN_RECEIVED, either: handshake done, RST, or SYN-ACK retries exhausted
	if (old == SYN_RECEIVED && state != SYN_RECEIVED && conn->lstnr)
		atomic_fetch_sub(&conn->lstnr->half_open_count, 1);

	// our FIN is acked, nothing left to retransmit or probe, but the peer
	// may still send data that we must ACK => keep the delayed-ACK timer
	if (state == FIN_WAIT_2) {
		d->cancel_snd_timers = true;
		conn->is_wndw_probing = false;
	}

	// TIME_WAIT / CLOSED: no more data either way
	if ((state == CLOSED || state == TIME_WAIT) && !conn->data_timers_cancelled) {
		conn->data_timers_cancelled = true;
		d->cancel_snd_timers = true;
		d->cancel_del_ack = true;
		conn->is_wndw_probing = false;
	}

	if (state == ESTABLISHED) {
		struct tcp_ipv4_listener *l = conn->lstnr;
		if (l) {
			if (!push_q(l->ready_q, &conn->q_node))
				d->abort = true;
		} else {
			pthread_cond_broadcast(&conn->estblshd_cond); // wake tcp_connect()
		}
	}

	// tcp_connect() waits for ESTABLISHED or CLOSED under conn->lock.
	// Readers and writers don't wait on the state: they're woken where their own conditions
	// change (data, FIN, room, shutdown, abort), under their own buffer's lock
	if (state == CLOSED)
		pthread_cond_broadcast(&conn->estblshd_cond);

	if (state == TIME_WAIT)
		d->enter_time_wait = true;
	if (state == CLOSED) {
		d->leave_time_wait = true;
		d->unhash = true;
	}
}

// does the work necessary after state transitions
// caller CANNOT hold conn->lock
// caller MUST hold own conn reference
void tcp_execute_deffered_work(struct tcp_ipv4_conn *conn, const struct tcp_deferred_work *d)
{
	struct tcp_context *ctx = (struct tcp_context *)conn->tcp_layer->context;
	struct timer_manager *tmgr = ctx->timer_mgr;
	struct socket_manager *smgr = ctx->socket_manager;

	if (d->cancel_snd_timers) {
		cancel_timer(tmgr, conn->rto_timer);
		cancel_timer(tmgr, conn->zwp_timer);
	}
	if (d->cancel_del_ack)
		cancel_timer(tmgr, conn->del_ack_timer);

	if (d->enter_time_wait) {
		add_to_tcp_conn_hashtable(smgr->tcp_ipv4_conn_time_wait_htable, conn);
		remove_from_tcp_conn_hashtable(smgr->tcp_ipv4_conn_htable, conn);
		start_timer(tmgr, conn->time_wait_timer, TCP_TIMEWAIT_MS);
	}

	if (d->leave_time_wait) {
		remove_from_tcp_conn_hashtable(smgr->tcp_ipv4_conn_time_wait_htable, conn);
		cancel_timer(tmgr, conn->time_wait_timer);
	}

	if (d->unhash)
		remove_from_tcp_conn_hashtable(smgr->tcp_ipv4_conn_htable, conn);

	if (d->pkt_snd_now) {
		conn->tcp_layer->send_down(conn->tcp_layer, d->pkt_snd_now);
		release_pkt(d->pkt_snd_now);
	}

	if (d->notify_TX_snd)
		notify_socket_readable_snd(smgr, conn, &tcp_conn_ops);

	if (d->abort)
		abort_tcp_conn(conn);
}

// takes lock, records deffered work, unlocks and executes the work
void tcp_transition_to_state(struct tcp_ipv4_conn *conn, tcp_connection_state state)
{
	struct tcp_deferred_work fx = {0};
	pthread_mutex_lock(&conn->lock);
	tcp_set_state_locked(conn, state, &fx);
	pthread_mutex_unlock(&conn->lock);
	tcp_execute_deffered_work(conn, &fx);
}

void tcp_retain_conn(void *s)
{
	struct tcp_ipv4_conn *conn = (struct tcp_ipv4_conn *)s;
	retain_tcp_conn(conn);
}

void retain_tcp_conn(struct tcp_ipv4_conn *conn)
{
	atomic_fetch_add(&conn->ref_count, 1);
}

void tcp_release_conn(void *s)
{
	struct tcp_ipv4_conn *conn = (struct tcp_ipv4_conn *)s;
	release_tcp_conn(conn);
}

void release_tcp_conn(struct tcp_ipv4_conn *conn)
{
	if (atomic_fetch_sub(&conn->ref_count, 1) == 1)
		destroy_tcp_conn(conn);
}

void q_retain_tcp_conn(struct queue_node *n)
{
	struct tcp_ipv4_conn *conn = CONTAINER_OF(n, struct tcp_ipv4_conn, q_node);
	retain_tcp_conn(conn);
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

// should only be called for connection that has transitioned to CLOSED state
void destroy_tcp_conn(struct tcp_ipv4_conn *conn)
{
	assert(conn->del_ack_timer->node.index == NODE_NOT_IN_HEAP
	       && conn->rto_timer->node.index == NODE_NOT_IN_HEAP
	       && conn->zwp_timer->node.index == NODE_NOT_IN_HEAP
	       && conn->time_wait_timer->node.index == NODE_NOT_IN_HEAP
	       && conn->data_timers_cancelled);

	printf("\n\nDESTROYING CONNECTION!! \n\n");

	destroy_byte_rcv_buffer(&conn->rcv_buffer);
	destroy_byte_snd_buffer(&conn->snd_buffer);
	free(conn->del_ack_timer);
	free(conn->rto_timer);
	free(conn->zwp_timer);
	free(conn->time_wait_timer);
	pthread_cond_destroy(&conn->estblshd_cond);
	pthread_mutex_destroy(&conn->lock);

	if (conn->lstnr)
		release_tcp_listener(conn->lstnr);

	free(conn);
}

// caller must hold conn lock
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
		if (tcp_seq_after_eq(b->ctrl[i].seq, seq)
		    && tcp_seq_before(b->ctrl[i].seq, seq + seq_len)) {
			p->tcp_flags |= b->ctrl[i].flags;
			payload_len--;
		}

	if (conn->state != SYN_SENT)
		p->tcp_flags |= TCP_ACK;

	// never send window value scaled in a SYN
	if (p->tcp_flags & TCP_SYN) {
		uint32_t bytes = (uint32_t)conn->rcv_buffer.rcv_wnd << conn->rcv_buffer.rcv_wscale;
		p->rcv_window = bytes > TCP_WND_FIELD_MAX ? TCP_WND_FIELD_MAX : bytes;
	}

	// add handshake options
	if (conn->state == SYN_SENT || conn->state == SYN_RECEIVED) {
		if (conn->wscale_enabled) {
			p->tcp_options->wscale_present = true;
			p->tcp_options->wscale = conn->rcv_buffer.rcv_wscale;
		}
		p->tcp_options->mss_present = true;
		p->tcp_options->mss = conn->rcv_mss;
		if (conn->sack_enabled)
			p->tcp_options->sack_permitted = true;
	}
	if (conn->ts_enabled)
		p->tcp_options->ts_present = true;

	// SACK blocks only in pure ACKs!

	// write data to packet buffer
	p->len = payload_len + sizeof(struct tcp_header_no_options)
		 + calc_tcp_options_len(p->tcp_options);

	if (p->len + sizeof(struct ipv4_header) + sizeof(struct ethernet_header) > PKT_SIZE) {
		assert(!"TCP segment larger than packet buffer");
		release_pkt(p);
		return NULL;
	}

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
	struct tcp_context *cntx = (struct tcp_context *)conn->tcp_layer->context;
	if ((p->tcp_flags & TCP_ACK) && conn->ack_pending) {
		conn->ack_pending = false;
		cancel_timer(cntx->timer_mgr, conn->del_ack_timer);
	}
	arm_tcp_data_timer_if_idle(conn, conn->rto_timer, conn->rto_interval);

	///////////////////////////////////////////////////////
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

	struct byte_snd_buffer *buff = &conn->snd_buffer;
	struct pkt *p;

	// safety net: retransmit request but no outstanding data
	// => continue to send new data instead
	if (buff->retransmit && buff->snd_una == buff->snd_nxt)
		buff->retransmit = false;

	uint32_t snd_seq = !buff->retransmit ? buff->snd_nxt : buff->snd_una;

	uint32_t tail_seq = buff->snd_una + (uint32_t)buff->used_bytes + buff->ctrl_count;
	uint32_t bytes_ready = tail_seq - snd_seq;
	printf("BYTES READY: %d \n", bytes_ready);
	if (bytes_ready == 0) {
		tcp_unlock_conn(conn);
		return NULL;
	}
	uint32_t peer_wndw;
	uint32_t usable_wndw = conn->state == SYN_SENT ? 1 : usable_window(conn, &peer_wndw);
	printf("WINDOW = %d \n", usable_wndw);
	if (usable_wndw == 0) {
		if (peer_wndw == 0)
			start_wndw_probing(conn);
		tcp_unlock_conn(conn);
		return NULL;
	}

	// in general we want to send MSS
	uint32_t min_bytes_snd = conn->snd_mss;

	// unless a SYN/FIN is coming up, then we just want to be able to send the amount of
	// bytes it takes to reach the control seq
	if (buff->ctrl_count > 0 && tcp_seq_after_eq(buff->ctrl[0].seq, snd_seq)) {
		uint32_t len_to_reach_ctrl = (buff->ctrl[0].seq - snd_seq) + 1;
		if (usable_wndw >= len_to_reach_ctrl && conn->snd_mss > len_to_reach_ctrl) {
			p = create_tcp_packet(conn, snd_seq, len_to_reach_ctrl);
			if (conn->is_wndw_probing)
				stop_wndw_probing(conn);
			tcp_unlock_conn(conn);
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

	if (usable_wndw < min_bytes_snd || min_bytes_snd < 1) {
		// if peer's window is smaller than amount of bytes we want to send
		// start probing ( => DON'T PROBE IF WE DON'T SEND BECAUSE PIPE TOO FULL)
		if (peer_wndw < min_bytes_snd) {
			printf("START PROBING DUE TO WINDOW = %d \n\n", peer_wndw);
			start_wndw_probing(conn);
		}
		tcp_unlock_conn(conn);
		return NULL;
	}

	printf("CREATING PKT SEQ: %u, LEN: %d \n", snd_seq, min_bytes_snd);
	p = create_tcp_packet(conn, snd_seq, min_bytes_snd);

	if (conn->is_wndw_probing)
		stop_wndw_probing(conn);
	tcp_unlock_conn(conn);

	return p;
}

void start_wndw_probing(struct tcp_ipv4_conn *conn)
{
	if (conn->is_wndw_probing)
		return;

	conn->is_wndw_probing = true;
	conn->zwp_interval = conn->rto_interval;
	if (conn->zwp_interval > TCP_MAX_ZWP_MS)
		conn->zwp_interval = TCP_MAX_ZWP_MS;
	printf("ZERO WINDOW TIMER STARTING AT %d MS", conn->zwp_interval);

	tcp_arm_data_timer(conn, conn->zwp_timer, conn->zwp_interval);
}

void stop_wndw_probing(struct tcp_ipv4_conn *conn)
{
	printf("STOP WINDOW PROBING!");
	conn->is_wndw_probing = false;
	struct timer_manager *timer_mgr =
	    (struct timer_manager *)((struct tcp_context *)conn->tcp_layer->context)->timer_mgr;
	cancel_timer(timer_mgr, conn->zwp_timer);
}

pkt_result tcp_send_packet(struct stack *stack, struct pkt *p)
{
	pkt_result r = stack->tcp_layer->send_down(stack->tcp_layer, p);

	// edit rcv_next, start timers, etc?
	return r;
}

void tcp_end_snd(void *sock)
{
	struct tcp_ipv4_conn *conn = (struct tcp_ipv4_conn *)sock;
	struct byte_snd_buffer *buff = &conn->snd_buffer;

	pthread_mutex_lock(&conn->lock);
	if (buff->shutdown) {
		pthread_mutex_unlock(&conn->lock);
		return;
	}

	struct tcp_deferred_work d = {0};

	// change state before sending out FIN
	// avoids ACK of our FIN coming in at stale state
	if (conn->state == ESTABLISHED) {
		tcp_set_state_locked(conn, FIN_WAIT_1, &d);
	} else if (conn->state == CLOSE_WAIT) {
		tcp_set_state_locked(conn, LAST_ACK, &d);
	} else {
		pthread_mutex_unlock(&conn->lock);
		return; // not in a state that sends a FIN
	}

	buff->shutdown = true;
	pthread_cond_broadcast(&buff->cond); // writers blocked on a full buffer: no more writing
	sndbuf_insert_ghost_byte(buff, TCP_FIN);
	d.notify_TX_snd = true;
	pthread_mutex_unlock(&conn->lock);
	tcp_execute_deffered_work(conn, &d);
}

void tcp_close_conn(struct stack *stack, void *sock)
{
	// tcp_end_snd checks the state itself, under the lock
	tcp_end_snd(sock);
}

ssize_t tcp_write_to_snd_buff(struct stack *stack, void *sock, struct send_request *req)
{
	if (!stack || !sock || !req->data || req->len < 1)
		return -1;

	struct tcp_ipv4_conn *conn = (struct tcp_ipv4_conn *)sock;
	struct tcp_deferred_work d = {0};

	pthread_mutex_lock(&conn->lock);
	ssize_t r = blocking_write_to_snd_buff(&conn->snd_buffer, req->data, req->len, conn);
	if (r > 0)
		d.notify_TX_snd = true;
	pthread_mutex_unlock(&conn->lock);
	tcp_execute_deffered_work(conn, &d);
	return r;
}

ssize_t tcp_read_from_rcv_buff(void *sock, size_t len, unsigned char *buff)
{
	if (!sock || len < 1 || !buff)
		return -1;
	struct tcp_ipv4_conn *conn = (struct tcp_ipv4_conn *)sock;
	struct tcp_deferred_work d = {0};
	pthread_mutex_lock(&conn->lock);

	struct byte_reassembly_rcv_buffer *b = &conn->rcv_buffer;

	bool prev_low_wndw = b->rcv_wnd < TCP_MSS_DEFAULT_FALLBACK;
	ssize_t r = blocking_read_from_rcv_buff(&conn->rcv_buffer, buff, len);
	printf("READ %ld BYTES FROM BUFFER!\n\n", r);
	b->rcv_wnd = calc_rcv_wnd_sws(conn);
	bool curr_low_wnwd = b->rcv_wnd < TCP_MSS_DEFAULT_FALLBACK;

	if (prev_low_wndw && !curr_low_wnwd) {
		printf("SEND WINDOW UPDATE!! NEW WINDOW: %u \n", b->rcv_wnd);
		struct pkt *p = allocate_pkt();
		if (p) {
			tcp_create_ack_reply(
			    p, conn, &d); // SEND WINDOW UPDATE!; retains pkt for d->pkt_snd_now
			release_pkt(p);
		}
	}

	pthread_mutex_unlock(&conn->lock);
	tcp_execute_deffered_work(conn, &d);
	return r;
}
