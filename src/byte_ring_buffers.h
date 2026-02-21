#pragma once
#include "tcp_common_types.h"
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define MAX_SACK_TRACKED 32	   // to avoind unneccessary retransmissions
#define MAX_OOO_RCV_SEG_STORED 256 // to avoid dropping data within window

struct out_of_order_segs {
	uint32_t seq;
	size_t len;
};

struct ctrl_seg {
	uint32_t seq;  // sequence number where this lives
	uint8_t flags; // TCP_SYN or TCP_FIN, only one each/connection
};

struct byte_reassembly_rcv_buffer {
	unsigned char *data;
	size_t capacity;

	pthread_mutex_t lock;
	pthread_cond_t data_ready;

	struct out_of_order_segs
	    ooo_segs[MAX_OOO_RCV_SEG_STORED]; // ordered by seq, binary search + shifting
	size_t ooo_count;
	size_t ooo_capacity;

	uint32_t rcv_nxt; // sequence number of the first "hole"
	size_t head;	  // physical index where the App starts reading

	size_t contiguous_bytes; // ready to be read by app
	size_t ooo_bytes;	 // total bytes stored in OOO segments

	uint32_t fin_seq;
	bool fin_received;
};

struct byte_snd_buffer {
	unsigned char *data;
	size_t capacity;

	pthread_mutex_t lock;
	pthread_cond_t space_ready;

	// SACK blocks received from peer
	struct out_of_order_segs sack_blocks[MAX_SACK_TRACKED];
	size_t sack_blocks_count;

	uint32_t snd_una; // lowest unacknowledged sequence number
	uint32_t snd_nxt; // next sequence number to be sent (moved back to snd_una on timeout)

	// physical indices
	size_t head;	     // index of snd_una (start of window)
	size_t next_to_send; // index of snd_nxt (where next_send starts)
	size_t tail;	     // index where the APP writes new data

	size_t used_bytes; // total bytes currently in buffer (sent + unsent)

	struct ctrl_seg ctrl[2]; // keep track of ghost bytes seqs
	size_t ctrl_count;	 // 0..2
};

struct byte_reassembly_rcv_buffer *create_init_byte_rcv_buffer(size_t capacity,
							       uint32_t initial_seq);
void destroy_byte_rcv_buffer(struct byte_reassembly_rcv_buffer *b);
struct byte_snd_buffer *create_init_byte_snd_buffer(size_t capacity, uint32_t initial_seq);
void destroy_byte_snd_buffer(struct byte_snd_buffer *b);
void sndbuf_insert_syn(struct byte_snd_buffer *b);
void sndbuf_insert_fin(struct byte_snd_buffer *b);