#include "ring_buffer.h"

bool write_to_udp_buffer(struct udp_ring_buffer_t *buff, struct pkt_t *packet)
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

struct pkt_t *read_udp_buffer(struct udp_ring_buffer_t *buff)
{
	pthread_mutex_lock(&buff->lock);
	if (buff->head == buff->tail) {
		pthread_mutex_unlock(&buff->lock);
		return NULL;
	}

	struct pkt_t *pkt = buff->packets[buff->tail];
	buff->tail = (buff->tail + 1) & (buff->length - 1);
	pthread_mutex_unlock(&buff->lock);
	// printf("READ: NEW TAIL: %d \n", buff->tail);

	return pkt;
}

struct pkt_t *read_udp_buffer_blocking(struct udp_ring_buffer_t *buff)
{
	pthread_mutex_lock(&buff->lock);
	while (buff->head == buff->tail) {
		pthread_cond_wait(&buff->cond, &buff->lock);
	}

	struct pkt_t *pkt = buff->packets[buff->tail];
	buff->tail = (buff->tail + 1) & (buff->length - 1);
	pthread_mutex_unlock(&buff->lock);
	// printf("READ: NEW TAIL: %d \n", buff->tail);

	return pkt;
}

struct udp_ring_buffer_t *create_init_udp_ring_buffer(size_t count)
{
	if (count == 0 || (count & (count - 1)) != 0)
		return NULL;

	struct udp_ring_buffer_t *buff = malloc(sizeof(struct udp_ring_buffer_t));
	if (buff == NULL)
		return NULL;
	buff->packets = calloc(count, sizeof(struct pkt_t));
	buff->length = count;
	pthread_mutex_init(&buff->lock, NULL);
	pthread_cond_init(&buff->cond, NULL);
	buff->head = 0;
	buff->tail = 0;
	return buff;
}