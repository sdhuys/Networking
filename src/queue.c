#include "queue.h"
#include <stdio.h>

struct queue *create_q(void (*release_parent)(struct queue_node *),
		       void (*retain_parent)(struct queue_node *),
		       pthread_cond_t *not_empty,
		       pthread_mutex_t *lock)
{
	struct queue *q = malloc(sizeof(*q));
	if (!q)
		return NULL;

	q->head = NULL;
	q->tail = NULL;
	q->release_parent = release_parent;
	q->retain_parent = retain_parent;
	q->lock = lock;
	q->not_empty = not_empty;
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

// if caller already holds lock, lock should be false
void push_q(struct queue *q, struct queue_node *n, bool lock)
{
	if (!q)
		return;
	if (q->lock && lock)
		pthread_mutex_lock(q->lock);
	n->nxt = NULL;
	if (q->head == NULL) {
		q->head = n;
		q->tail = n;
	}

	else {
		n->nxt = q->tail->nxt;
		q->tail->nxt = n;
		q->tail = n;
	}
	if (q->retain_parent)
		q->retain_parent(n);

	if (q->head->nxt == NULL && q->not_empty)
		pthread_cond_signal(q->not_empty);

	if (q->lock && lock)
		pthread_mutex_unlock(q->lock);
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

	if (q->lock)
		pthread_mutex_unlock(q->lock);
	return r;
}

struct queue_node *pop_q_blocking(struct queue *q)
{
	pthread_mutex_lock(q->lock);

	while (q->head == NULL) {
		pthread_cond_wait(q->not_empty, q->lock);
	}

	struct queue_node *r = q->head;
	q->head = r->nxt;
	if (!q->head)
		q->tail = NULL;

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