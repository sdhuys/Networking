#include "byte_ring_buffers.h"

struct byte_reassembly_rcv_buffer *create_init_byte_rcv_buffer(size_t capacity,
							       uint32_t initial_seq)
{
	if (capacity == 0)
		return NULL;

	struct byte_reassembly_rcv_buffer *b = malloc(sizeof(*b));
	if (!b)
		return NULL;

	b->data = malloc(capacity);
	if (!b->data) {
		free(b);
		return NULL;
	}

	b->capacity = capacity;
	b->ooo_count = 0;
	b->ooo_capacity = MAX_OOO_RCV_SEG_STORED;
	b->ooo_bytes = 0;

	b->rcv_nxt = initial_seq;
	b->contiguous_bytes = 0;
	b->head = 0;

	pthread_mutex_init(&b->lock, NULL);
	pthread_cond_init(&b->data_ready, NULL);

	return b;
}

void destroy_byte_rcv_buffer(struct byte_reassembly_rcv_buffer *b)
{
	if (!b)
		return;

	pthread_mutex_destroy(&b->lock);
	pthread_cond_destroy(&b->data_ready);

	free(b->data);
	free(b);
}

struct byte_snd_buffer *create_init_byte_snd_buffer(size_t capacity, uint32_t initial_seq)
{
	if (capacity == 0)
		return NULL;

	struct byte_snd_buffer *b = malloc(sizeof(*b));
	if (!b)
		return NULL;

	b->data = malloc(capacity);
	if (!b->data) {
		free(b);
		return NULL;
	}

	b->capacity = capacity;
	b->used_bytes = 0;

	b->snd_una = initial_seq;
	b->snd_nxt = initial_seq;

	b->head = 0;
	b->next_to_send = 0;
	b->tail = 0;

	b->sack_blocks_count = 0;
	memset(b->sack_blocks, 0, sizeof(b->sack_blocks));

	pthread_mutex_init(&b->lock, NULL);
	pthread_cond_init(&b->space_ready, NULL);

	return b;
}

void destroy_byte_snd_buffer(struct byte_snd_buffer *b)
{
	if (!b)
		return;

	pthread_mutex_destroy(&b->lock);
	pthread_cond_destroy(&b->space_ready);

	free(b->data);
	free(b);
}

void sndbuf_insert_syn(struct byte_snd_buffer *b)
{
	b->ctrl[b->ctrl_count++] = (struct ctrl_seg){.seq = b->snd_nxt, .flags = TCP_SYN};
	b->snd_nxt++;
}

void sndbuf_insert_fin(struct byte_snd_buffer *b)
{
	b->ctrl[b->ctrl_count++] =
	    (struct ctrl_seg){.seq = b->snd_nxt + b->used_bytes, .flags = TCP_FIN};
}
