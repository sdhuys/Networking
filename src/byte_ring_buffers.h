#pragma once
#include "tcp_segment.h"
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CTRL_BLOCKS 2
#define MAX_SACK_TRACKED 32	  // to avoind unneccessary retransmissions
#define MAX_OOO_RCV_SEG_STORED 64 // to avoid dropping data within window

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

	uint16_t rcv_wnd; // our last advertised rcv_window

	uint32_t rcv_nxt; // sequence number of the first "hole"
	size_t head;	  // physical index where the App starts reading
	size_t tail;	  // physical index of rcv_nxt

	size_t contiguous_bytes; // ready to be read by app

	uint32_t fin_seq;
	bool fin_received;
};

struct byte_snd_buffer {
	unsigned char *data;
	size_t capacity;

	pthread_mutex_t lock;
	pthread_cond_t cond;

	// SACK blocks received from peer
	struct ooo_seg sack_blocks[MAX_SACK_TRACKED];
	size_t sack_blocks_count;
	size_t sacked_bytes;

	uint32_t snd_una; // lowest unacknowledged sequence number
	uint32_t snd_nxt; // next sequence number to be sent

	// physical indices
	size_t head;	  // index of snd_una (start of window)
	size_t snd_nxt_i; // index of snd_nxt (middle)
	size_t tail; // index where the APP writes new data (end of current data, possibly outside
		     // of window)

	bool rcov_mode;
	uint32_t rcov_snd_next; // recovery mode sequence number to be sent
	size_t rcov_snd_nxt_i;	// physical index of rcov_snd_next

	size_t used_bytes; // total bytes currently in buffer (sent + unsent)

	struct ctrl_seg ctrl[CTRL_BLOCKS]; // keep track of ghost bytes seqs
	uint8_t ctrl_count;		   // 0..2
};

struct byte_reassembly_rcv_buffer *create_byte_rcv_buffer(size_t capacity);
void destroy_byte_rcv_buffer(struct byte_reassembly_rcv_buffer *b);
struct byte_snd_buffer *create_byte_snd_buffer(size_t capacity);
void destroy_byte_snd_buffer(struct byte_snd_buffer *b);
size_t write_to_snd_buff(struct byte_snd_buffer *b, unsigned char *data, size_t len);
size_t copy_bytes_to_snd_from_snd_buff(struct byte_snd_buffer *b, unsigned char *buffer, size_t len);

size_t rcv_buffer_write_tcp_segment(struct byte_reassembly_rcv_buffer *b, struct tcp_segment *seg);

static inline void sndbuf_insert_ghost_byte(struct byte_snd_buffer *b, uint8_t flag)
{
	if (flag != TCP_SYN && flag != TCP_FIN)
		return;
	b->ctrl[b->ctrl_count++] = (struct ctrl_seg){.seq = b->snd_nxt, .flags = TCP_SYN};
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
}