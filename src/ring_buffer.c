#include "ring_buffer.h"

bool write_to_buffer(struct ring_buffer_t *buff, struct pkt_t *packet)
{
	printf("WRITE FROM HEAD %d \n", buff->head);
	pthread_mutex_lock(&buff->lock);
	uint32_t next_head = (buff->head + 1) % RING_BUFF_SIZE;
	if (next_head == buff->tail) {
		pthread_mutex_unlock(&buff->lock);
		return false;
	}

	buff->packets[buff->head] = packet;
	buff->head = next_head;
	printf("WRITTEN: NEW HEAD: %d \n", buff->head);
	pthread_mutex_unlock(&buff->lock);
	return true;
}

struct pkt_t *read_buffer(struct ring_buffer_t *buff)
{
	pthread_mutex_lock(&buff->lock);
	if (buff->head == buff->tail) {
		pthread_mutex_unlock(&buff->lock);
		return NULL;
	}

	struct pkt_t *pkt = buff->packets[buff->tail];
	buff->tail = (buff->tail + 1) % RING_BUFF_SIZE;
	pthread_mutex_unlock(&buff->lock);
	printf("READ: NEW TAIL: %d \n", buff->tail);

	return pkt;
}