#pragma once
#include "types.h"
#include <stdio.h>
#include <stdlib.h>

struct udp_ring_buffer_t {
	struct pkt_t **packets; // array of pkt pointers!
	uint32_t head;
	uint32_t tail;
	pthread_mutex_t lock;
	size_t length;
};

struct udp_ring_buffer_t *create_init_udp_ring_buffer(size_t size);
bool write_to_udp_buffer(struct udp_ring_buffer_t *buff, struct pkt_t *packet);
struct pkt_t *read_udp_buffer(struct udp_ring_buffer_t *buff);

struct tcp_snd_ring_buffer_t {
	struct pkt_t **packets;
	uint32_t head;
	uint32_t ack_pos;
	uint32_t tail;
	pthread_mutex_t lock;
};

struct tcp_rcv_ring_buffer_t {
	struct pkt_t **packets;
	uint32_t head;
	uint32_t tail;
	pthread_mutex_t lock;
};

// out of order buffer
struct tcp_ooo_ring_buffer_t {
};
