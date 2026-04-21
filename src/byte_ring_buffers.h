#pragma once
#include "tcp_common_types.h"
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define CTRL_BLOCKS 2
#define MAX_SACK_TRACKED 32	  // to avoind unneccessary retransmissions
#define MAX_OOO_RCV_SEG_STORED 64 // to avoid dropping data within window

struct tcp_ipv4_conn;
struct tcp_segment;

struct ctrl_seg {
	uint32_t seq;  // sequence number where this lives
	uint8_t flags; // TCP_SYN (+ACK/ECE/CWR) or TCP_FIN, only one each/connection
};

struct byte_reassembly_rcv_buffer {
	unsigned char *data;
	size_t capacity;

	pthread_mutex_t lock;
	pthread_cond_t cond;

	struct ooo_seg ooo_segs[MAX_OOO_RCV_SEG_STORED]; // ordered by seq, binary search + shifting
	size_t ooo_count;
	size_t ooo_capacity;

	uint16_t rcv_wnd;   // our last advertised rcv_window
	uint8_t rcv_wscale; // our scale

	uint32_t rcv_nxt; // sequence number of the first "hole"
	size_t head;	  // physical index where the App starts reading
	size_t tail;	  // physical index of rcv_nxt

	size_t contiguous_bytes; // ready to be read by app

	uint32_t fin_seq;
	bool fin_received;
	uint32_t consumed_seq;
};

struct byte_snd_buffer {
	unsigned char *data;
	size_t capacity;

	pthread_mutex_t lock;
	pthread_cond_t cond;

	// SACK blocks received from peer
	struct ooo_seg sack_blocks[MAX_SACK_TRACKED];
	size_t sack_blocks_count;
	size_t sack_capacity;
	size_t sacked_bytes;

	uint32_t snd_una; // lowest unacknowledged sequence number
	uint32_t snd_nxt; // next sequence number to be sent

	// physical indices
	size_t head;	  // index of snd_una (start of window)
	size_t snd_nxt_i; // index of snd_nxt (middle)
	size_t tail; // index where the APP writes new data (end of current data, possibly outside
		     // of window)

	bool rcov_mode;
	uint32_t rcov_snd_nxt; // recovery mode sequence number to be sent
	size_t rcov_snd_nxt_i; // physical index of rcov_snd_next

	size_t used_bytes; // total bytes currently in buffer (unacked sent + unsent)

	uint16_t snd_wndw;  // peer's advertised window (not scaled)
	uint8_t snd_wscale; // peer's scale

	uint32_t cwnd;
	uint32_t ssthresh;

	struct ctrl_seg ctrl[CTRL_BLOCKS]; // keep track of ghost bytes seqs
	uint8_t ctrl_count;		   // 0..2
};

#ifdef __cplusplus
extern "C" {
#endif

int init_byte_rcv_buffer(struct byte_reassembly_rcv_buffer *b, size_t capacity);
void destroy_byte_rcv_buffer(struct byte_reassembly_rcv_buffer *b);
int init_byte_snd_buffer(struct byte_snd_buffer *b, size_t capacity);
void destroy_byte_snd_buffer(struct byte_snd_buffer *b);
size_t write_to_snd_buff(struct byte_snd_buffer *b, unsigned char *data, size_t len);
ssize_t blocking_write_to_snd_buff(struct byte_snd_buffer *b,
				   unsigned char *data,
				   size_t len,
				   struct tcp_ipv4_conn *conn);
ssize_t blocking_write_all_to_snd_buff(struct byte_snd_buffer *b, unsigned char *data, size_t len);
void read_from_snd_buff(struct byte_snd_buffer *b, unsigned char *buffer, size_t len);
void insert_ooo_segment(
    struct ooo_seg *segs, size_t *count, size_t capacity, struct ooo_seg seg, size_t idx);
size_t bin_search_seq_after_eq_indx(uint32_t seq, struct ooo_seg *segs, size_t count);
size_t rcv_buffer_write_tcp_segment(struct byte_reassembly_rcv_buffer *b,
				    struct tcp_segment *seg,
				    bool *immediate_ack);

ssize_t blocking_read_from_rcv_buff(struct byte_reassembly_rcv_buffer *b,
				    unsigned char *buffer,
				    size_t len);

static inline void sndbuf_insert_ghost_byte(struct byte_snd_buffer *b, uint8_t flag)
{
	if ((flag != TCP_SYN && flag != TCP_FIN) || b->ctrl_count == 2)
		return;
	uint32_t tail_seq = b->snd_una + (uint32_t)b->used_bytes;
	size_t unsent_bytes = tail_seq - b->snd_nxt;
	b->ctrl[b->ctrl_count++] =
	    (struct ctrl_seg){.seq = b->snd_nxt + unsent_bytes, .flags = flag};
}

static inline void lock_snd_buff(struct byte_snd_buffer *buff)
{
	pthread_mutex_lock(&buff->lock);
}

static inline void unlock_snd_buff(struct byte_snd_buffer *buff)
{
	pthread_mutex_unlock(&buff->lock);
}

// snd buff always only in order data
static inline size_t sndbuff_available_space(struct byte_snd_buffer *buff)
{
	return buff->capacity - buff->used_bytes;
}

static inline void lock_rcv_buff(struct byte_reassembly_rcv_buffer *buff)
{
	pthread_mutex_lock(&buff->lock);
}

static inline void unlock_rcv_buff(struct byte_reassembly_rcv_buffer *buff)
{
	pthread_mutex_unlock(&buff->lock);
}

static inline size_t rcvbuf_available_space(struct byte_reassembly_rcv_buffer *buff)
{
	return buff->capacity - (buff->contiguous_bytes);
}

static inline size_t seq_to_index(struct byte_reassembly_rcv_buffer *b, uint32_t seq)
{
	// calculate how far 'seq' is from 'rcv_nxt' in sequence space
	// TCP sequence arithmetic handles the wrap-around automatically here
	uint32_t offset = seq - b->rcv_nxt;

	// map that offset starting from the physical 'tail'.
	// using modulo capacity to wrap around the physical memory array
	return (b->tail + offset) & (b->capacity - 1);
}

static inline void update_rcv_nxt_tail(struct byte_reassembly_rcv_buffer *b, size_t contiguous_add)
{
	b->rcv_nxt += contiguous_add;
	b->tail = (b->tail + contiguous_add) & (b->capacity - 1);
	b->contiguous_bytes += contiguous_add;
}

static inline void update_snd_nxt_head(struct byte_snd_buffer *b,
				       uint32_t seg_ack,
				       size_t data_ackd)
{
	b->snd_una = seg_ack;
	b->used_bytes -= data_ackd;
	b->head = (b->head + data_ackd) & (b->capacity - 1);
}

// only store SACKs if start < end
// AND end after seg_ack but before_eq snd_next
// AND space to store OR ealier than last stored
static inline bool should_store_sack_block(struct byte_snd_buffer *sb,
					   uint32_t s_start,
					   uint32_t s_end,
					   uint32_t seg_ack)
{
	return tcp_seq_before(s_start, s_end) && tcp_seq_after(s_end, seg_ack) &&
	       tcp_seq_before_eq(s_end, sb->snd_nxt) &&
	       (sb->sack_blocks_count < sb->sack_capacity ||
		tcp_seq_before_eq(s_start, sb->sack_blocks[sb->sack_capacity - 1].start_seq));
}

#ifdef __cplusplus
}
#endif
