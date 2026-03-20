#pragma once
#include "container_of.h"
#include "stdlib.h"
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>

struct queue_node {
	struct queue_node *nxt;
};

struct queue {
	struct queue_node *head;
	struct queue_node *tail;
	pthread_mutex_t *lock;
	pthread_cond_t *not_empty;
	void (*release_parent)(struct queue_node *);
	void (*retain_parent)(struct queue_node *);
};

struct queue *create_q(void (*release_parent)(struct queue_node *),
		       void (*retain_parent)(struct queue_node *),
		       pthread_cond_t *cond,
		       pthread_mutex_t *lock);
void destroy_q(struct queue *q);
void push_q(struct queue *q, struct queue_node *n, bool lock);
struct queue_node *pop_q(struct queue *q);
struct queue_node *pop_q_blocking(struct queue *q);
struct queue_node *peek_q(struct queue *q);