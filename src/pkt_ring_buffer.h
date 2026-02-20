#pragma once
#include "types.h"
#include <stdio.h>
#include <stdlib.h>

struct pkt_ring_buffer {
	struct pkt **packets; // array of pkt pointers!
	uint32_t head;
	uint32_t tail;
	pthread_mutex_t lock;
	pthread_cond_t cond; // only used in receive buffers! (send buffers go through send q)
	size_t length;
};

struct pkt_ring_buffer *create_init_pkt_ring_buffer(size_t size);
void destroy_pkt_ring_buffer(struct pkt_ring_buffer *b);
bool write_to_pkt_buffer(struct pkt_ring_buffer *buff, struct pkt *packet);
struct pkt *read_pkt_buffer(struct pkt_ring_buffer *buff);	    // TX
struct pkt *read_pkt_buffer_blocking(struct pkt_ring_buffer *buff); // RX
