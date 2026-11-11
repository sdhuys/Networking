#include "buffer_pool.h"
#include "pkt.h"
#include "tcp_options.h"
#include <assert.h>
#include <stdalign.h>
#include <stdio.h>

alignas(64) static unsigned char buffer_pool[PKT_BUFF_POOL_SIZE][PKT_SIZE];
static struct pkt pkt_pool[PKT_BUFF_POOL_SIZE];
static struct pkt *free_pkt_stack[PKT_BUFF_POOL_SIZE];
static int top_free_index;
static pthread_mutex_t pool_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct tcp_options tcp_opts[PKT_BUFF_POOL_SIZE];

void init_buffer_pool()
{
	pthread_mutex_lock(&pool_mutex);

	for (int i = 0; i < PKT_BUFF_POOL_SIZE; i++) {
		pkt_pool[i].data = buffer_pool[i];
		pkt_pool[i].tcp_options = &tcp_opts[i];
		pkt_pool[i].ref_count = 0;
		free_pkt_stack[i] = &pkt_pool[i];
		pkt_pool[i].pool_index = i;
	}
	top_free_index = PKT_BUFF_POOL_SIZE - 1;

	pthread_mutex_unlock(&pool_mutex);
}

struct pkt *allocate_pkt()
{
	pthread_mutex_lock(&pool_mutex);

	if (top_free_index < 0) {
		pthread_mutex_unlock(&pool_mutex);
		return NULL;
	}

	struct pkt *p = free_pkt_stack[top_free_index--];
	printf("Allocating %d id, %d ref count, %d top_free_index \n",
	       p->pool_index,
	       p->ref_count,
	       top_free_index + 1);
	p->ref_count = 1;
	p->route = NULL;

	pthread_mutex_unlock(&pool_mutex);
	return p;
}

void release_pkt(struct pkt *pkt)
{
	unsigned int old = atomic_fetch_sub(&pkt->ref_count, 1);
	assert(old > 0);

	printf("Released PACKET %d id, %d ref count \n", pkt->pool_index, old - 1);

	if (old == 1) {
		printf("=> RETURN TO POOL");
		pthread_mutex_lock(&pool_mutex);
		free_pkt_stack[++top_free_index] = pkt;
		pthread_mutex_unlock(&pool_mutex);
	}
	printf("\n\n");
}

void retain_pkt(struct pkt *pkt)
{
	unsigned int old = atomic_fetch_add(&pkt->ref_count, 1);
	printf("Retained PACKET %d id, %d ref count \n", pkt->pool_index, old + 1);
}
