#include "buffer_pool.h"
#include "container_of.h"
#include "pkt.h"
#include "tcp_options.h"
#include <assert.h>
#include <stdalign.h>
#include <stdio.h>
#include <string.h>

alignas(64) static unsigned char buffer_pool[PKT_BUFF_POOL_SIZE][PKT_SIZE];
static struct pkt pkt_pool[PKT_BUFF_POOL_SIZE];
static struct pkt *free_pkt_stack[PKT_BUFF_POOL_SIZE];
static int top_free_index;
static pthread_mutex_t pool_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t pool_not_empty = PTHREAD_COND_INITIALIZER;
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

static void init_allocated_pkt(struct pkt *p)
{
	p->ref_count = 1;
	p->route = NULL;
	memset(p->tcp_options, 0, sizeof(*p->tcp_options));
	p->q_node.nxt = Q_NODE_UNLINKED;
}

// blocks until a packet is free, only for interface reader thread
struct pkt *allocate_pkt_wait()
{
	pthread_mutex_lock(&pool_mutex);
	while (top_free_index < 0)
		pthread_cond_wait(&pool_not_empty, &pool_mutex);
	struct pkt *p = free_pkt_stack[top_free_index--];
	pthread_mutex_unlock(&pool_mutex);
	init_allocated_pkt(p);
	return p;
}

// sets ref_count to 1 (implicit retain)
struct pkt *allocate_pkt()
{
	pthread_mutex_lock(&pool_mutex);

	if (top_free_index < 0) {
		pthread_mutex_unlock(&pool_mutex);
		return NULL;
	}
	struct pkt *p = free_pkt_stack[top_free_index--];
	pthread_mutex_unlock(&pool_mutex);
	init_allocated_pkt(p);

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
		pthread_cond_signal(&pool_not_empty);
		pthread_mutex_unlock(&pool_mutex);
	}
	printf("\n\n");
}

void retain_pkt(struct pkt *pkt)
{
	unsigned int old = atomic_fetch_add(&pkt->ref_count, 1);
	printf("Retained PACKET %d id, %d ref count \n", pkt->pool_index, old + 1);
}

void q_release_pkt(struct queue_node *n)
{
	struct pkt *p = CONTAINER_OF(n, struct pkt, q_node);
	release_pkt(p);
}

void q_retain_pkt(struct queue_node *n)
{
	struct pkt *p = CONTAINER_OF(n, struct pkt, q_node);
	retain_pkt(p);
}
