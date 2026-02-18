#pragma once
#include "types.h"
#include <stdio.h>
#include <stdlib.h>

struct ring_buffer {
	struct pkt **packets; // array of pkt pointers!
	uint32_t head;
	uint32_t tail;
	pthread_mutex_t lock;
	pthread_cond_t cond; // only used in receive buffers! (send buffers go through send q)
	size_t length;
};

struct ring_buffer *create_init_ring_buffer(size_t size);
bool write_to_buffer(struct ring_buffer *buff, struct pkt *packet);
struct pkt *read_buffer(struct ring_buffer *buff);	    // TX
struct pkt *read_buffer_blocking(struct ring_buffer *buff); // RX

// out of order buffer
struct tcp_ooo_ring_buffer {
	struct ring_buffer buff;
	size_t fill_count; //
};
