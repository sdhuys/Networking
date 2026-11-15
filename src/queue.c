#include "queue.h"
#include "container_of.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

struct queue *create_q(void (*release_parent)(struct queue_node *),
		       void (*retain_parent)(struct queue_node *),
		       pthread_cond_t *not_empty,
		       pthread_mutex_t *lock,
		       size_t cap)
{
	struct queue *q = malloc(sizeof(*q));
	if (!q)
		return NULL;

	q->head = NULL;
	q->tail = NULL;
	q->release_parent = release_parent;
	q->retain_parent = retain_parent;
	q->lock = lock;
	q->not_empty_or_closed = not_empty;
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
	free(q);
}

bool push_q(struct queue *q, struct queue_node *n)
{
	assert(n->nxt == Q_NODE_UNLINKED);
	if (!q)
		return false;
	if (q->lock)
		pthread_mutex_lock(q->lock);

	if ((q->cap && q->count == q->cap) || q->closed) {
		if (q->lock)
			pthread_mutex_unlock(q->lock);
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
	if (q->not_empty_or_closed)
		pthread_cond_signal(q->not_empty_or_closed);

	if (q->lock)
		pthread_mutex_unlock(q->lock);

	return true;
}

// no release_parent call, ownership transferred to caller
struct queue_node *pop_q(struct queue *q)
{
	if (!q)
		return NULL;

	if (q->lock)
		pthread_mutex_lock(q->lock);

	struct queue_node *r = q->head;
	if (!r) {
		if (q->lock)
			pthread_mutex_unlock(q->lock);
		return NULL;
	}

	q->head = q->head->nxt;

	if (!q->head)
		q->tail = NULL;

	q->count--;
	r->nxt = Q_NODE_UNLINKED;
	if (q->lock)
		pthread_mutex_unlock(q->lock);
	return r;
}

struct queue_node *pop_q_blocking(struct queue *q)
{
	pthread_mutex_lock(q->lock);

	while (q->head == NULL && !q->closed) {
		pthread_cond_wait(q->not_empty_or_closed, q->lock);
	}

	if (q->closed) {
		pthread_mutex_unlock(q->lock);
		return NULL;
	}

	struct queue_node *r = q->head;
	q->head = r->nxt;
	if (!q->head)
		q->tail = NULL;

	r->nxt = Q_NODE_UNLINKED;
	q->count--;
	pthread_mutex_unlock(q->lock);
	return r;
}

void close_q(struct queue *q)
{
	pthread_mutex_lock(q->lock);
	q->closed = true;
	if (q->not_empty_or_closed)
		pthread_cond_broadcast(q->not_empty_or_closed);
	pthread_mutex_unlock(q->lock);
}

bool q_full(struct queue *q)
{
	if (q->lock)
		pthread_mutex_lock(q->lock);
	bool r = q->cap && q->cap == q->count;
	if (q->lock)
		pthread_mutex_unlock(q->lock);
	return r;
}

// not thread safe
struct queue_node *peek_q(struct queue *q)
{
	if (!q)
		return NULL;

	return q->head;
}