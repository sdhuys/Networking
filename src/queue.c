#include "queue.h"
#include "container_of.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

struct queue *create_q(void (*release_parent)(struct queue_node *),
		       void (*retain_parent)(struct queue_node *),
		       size_t cap)
{
	struct queue *q = malloc(sizeof(*q));
	if (!q)
		return NULL;
	if (pthread_mutex_init(&q->lock, NULL) != 0) {
		free(q);
		return NULL;
	}
	if (pthread_cond_init(&q->not_empty_or_closed, NULL) != 0) {
		pthread_mutex_destroy(&q->lock);
		free(q);
		return NULL;
	}

	q->head = NULL;
	q->tail = NULL;
	q->release_parent = release_parent;
	q->retain_parent = retain_parent;
	q->cap = cap;
	q->count = 0;
	q->closed = false;
	return q;
}

void destroy_q(struct queue *q)
{
	if (!q)
		return;

	struct queue_node *curr = q->head;
	while (curr) {
		struct queue_node *nxt = curr->nxt;

		if (q->release_parent)
			q->release_parent(curr);
		curr = nxt;
	}
	pthread_mutex_destroy(&q->lock);
	pthread_cond_destroy(&q->not_empty_or_closed);
	free(q);
}

bool push_q(struct queue *q, struct queue_node *n)
{
	assert(n->nxt == Q_NODE_UNLINKED);
	if (!q)
		return false;

	pthread_mutex_lock(&(q->lock));

	if ((q->cap && q->count == q->cap) || q->closed) {
		pthread_mutex_unlock(&(q->lock));
		return false; // no retain: caller still owns n
	}
	n->nxt = NULL;
	q->count++;

	if (q->head == NULL) {
		q->head = n;
		q->tail = n;
	}

	else {
		q->tail->nxt = n;
		q->tail = n;
	}
	if (q->retain_parent)
		q->retain_parent(n);

	// signal on each push
	// if two threads are waiting in accept() one could sleep forever if we only signal when
	// queue was empty
	pthread_cond_signal(&(q->not_empty_or_closed));
	pthread_mutex_unlock(&(q->lock));

	return true;
}

// no release_parent call, ownership transferred to caller
struct queue_node *pop_q(struct queue *q)
{
	if (!q)
		return NULL;

	pthread_mutex_lock(&(q->lock));

	struct queue_node *r = q->head;
	if (!r) {
		pthread_mutex_unlock(&(q->lock));
		return NULL;
	}

	q->head = q->head->nxt;

	if (!q->head)
		q->tail = NULL;

	q->count--;
	r->nxt = Q_NODE_UNLINKED;
	pthread_mutex_unlock(&(q->lock));
	return r;
}

struct queue_node *pop_q_blocking(struct queue *q)
{
	pthread_mutex_lock(&(q->lock));

	while (q->head == NULL && !q->closed) {
		pthread_cond_wait(&(q->not_empty_or_closed), &(q->lock));
	}

	if (q->closed) {
		pthread_mutex_unlock(&(q->lock));
		return NULL;
	}

	struct queue_node *r = q->head;
	q->head = r->nxt;
	if (!q->head)
		q->tail = NULL;

	r->nxt = Q_NODE_UNLINKED;
	q->count--;
	pthread_mutex_unlock(&(q->lock));
	return r;
}
// marks the queue closed
// detaches all nodes from the queue
// returns old head of the queue for safe disposal without holding queue lock
struct queue_node *close_q(struct queue *q)
{
	pthread_mutex_lock(&(q->lock));
	q->closed = true;
	struct queue_node *list = q->head;
	q->head = q->tail = NULL;
	q->count = 0;
	pthread_cond_broadcast(&(q->not_empty_or_closed));
	pthread_mutex_unlock(&(q->lock));
	return list;
}

bool q_full(struct queue *q)
{

	pthread_mutex_lock(&(q->lock));
	bool r = q->cap && q->cap == q->count;
	pthread_mutex_unlock(&(q->lock));
	return r;
}

// not thread safe
struct queue_node *peek_q(struct queue *q)
{
	if (!q)
		return NULL;

	return q->head;
}