#include "buffer_pool.h"

alignas(64) static unsigned char buffer_pool[PKT_BUFF_POOL_SIZE][MAX_ETH_FRAME_SIZE];
static struct pkt_t pkt_pool[PKT_BUFF_POOL_SIZE];
static struct pkt_t *free_pkt_stack[PKT_BUFF_POOL_SIZE];
static int top_free_index;
static pthread_mutex_t pool_mutex = PTHREAD_MUTEX_INITIALIZER;

void init_buffer_pool()
{
	pthread_mutex_lock(&pool_mutex);

	for (int i = 0; i < PKT_BUFF_POOL_SIZE; i++) {
		pkt_pool[i].data = buffer_pool[i];
		pkt_pool[i].ref_count = 0;
		pthread_mutex_init(&pkt_pool[i].lock, NULL);
		free_pkt_stack[i] = &pkt_pool[i];
	}
	top_free_index = PKT_BUFF_POOL_SIZE - 1;

	pthread_mutex_unlock(&pool_mutex);
}

struct pkt_t *allocate_pkt()
{
	pthread_mutex_lock(&pool_mutex);

	if (top_free_index < 0) {
		pthread_mutex_unlock(&pool_mutex);
		return NULL;
	}

	struct pkt_t *p = free_pkt_stack[top_free_index--];
	p->ref_count = 1;

	pthread_mutex_unlock(&pool_mutex);
	return p;
}

void release_pkt(struct pkt_t *pkt)
{
    int should_free = 0;

    pthread_mutex_lock(&pkt->lock);
    if (--pkt->ref_count == 0)
        should_free = 1;
    pthread_mutex_unlock(&pkt->lock);

    if (should_free) {
        pthread_mutex_lock(&pool_mutex);
        free_pkt_stack[++top_free_index] = pkt;
        pthread_mutex_unlock(&pool_mutex);
    }
}


void retain_pkt(struct pkt_t *pkt)
{
	pthread_mutex_lock(&pkt->lock);
	pkt->ref_count++;
	pthread_mutex_unlock(&pkt->lock);
}
