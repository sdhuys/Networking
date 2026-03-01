#include "pkt_ring_buffer.h"

bool write_to_pkt_buffer(struct pkt_ring_buffer *buff, struct pkt *packet)
{
	// printf("WRITE FROM HEAD %d \n", buff->head);
	pthread_mutex_lock(&buff->lock);
	uint32_t next_head = (buff->head + 1) & (buff->length - 1);
	if (next_head == buff->tail) {
		pthread_mutex_unlock(&buff->lock);
		return false;
	}

	buff->packets[buff->head] = packet;
	buff->head = next_head;
	// printf("WRITTEN: NEW HEAD: %d \n", buff->head);
	pthread_mutex_unlock(&buff->lock);
	return true;
}

bool pkt_buffer_empty(struct pkt_ring_buffer *buff)
{
	return buff->head == buff->tail;
}

struct pkt *read_pkt_buffer(struct pkt_ring_buffer *buff)
{
	pthread_mutex_lock(&buff->lock);
	if (buff->head == buff->tail) {
		pthread_mutex_unlock(&buff->lock);
		return NULL;
	}

	struct pkt *pkt = buff->packets[buff->tail];
	buff->tail = (buff->tail + 1) & (buff->length - 1);
	pthread_mutex_unlock(&buff->lock);
	// printf("READ: NEW TAIL: %d \n", buff->tail);

	return pkt;
}

struct pkt *read_pkt_buffer_blocking(struct pkt_ring_buffer *buff)
{
	pthread_mutex_lock(&buff->lock);
	while (buff->head == buff->tail) {
		pthread_cond_wait(&buff->cond, &buff->lock);
	}

	struct pkt *pkt = buff->packets[buff->tail];
	buff->tail = (buff->tail + 1) & (buff->length - 1);
	pthread_mutex_unlock(&buff->lock);
	// printf("READ: NEW TAIL: %d \n", buff->tail);

	return pkt;
}

struct pkt_ring_buffer *create_init_pkt_ring_buffer(size_t capacity)
{
	if (capacity == 0 || (capacity & (capacity - 1)) != 0)
		return NULL;

	struct pkt_ring_buffer *buff = malloc(sizeof(struct pkt_ring_buffer));
	if (buff == NULL)
		return NULL;
	buff->packets = calloc(capacity, sizeof(struct pkt));
	buff->length = capacity;
	pthread_mutex_init(&buff->lock, NULL);
	pthread_cond_init(&buff->cond, NULL);
	buff->head = 0;
	buff->tail = 0;
	return buff;
}

void destroy_pkt_ring_buffer(struct pkt_ring_buffer *b)
{
	if (!b)
		return;

	pthread_mutex_destroy(&b->lock);
	pthread_cond_destroy(&b->cond);
	free(b->packets);
	free(b);
}
