#pragma once
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>

#define Q_NODE_UNLINKED ((struct queue_node *)0x1)

struct queue_node {
	struct queue_node *nxt;
};

struct queue {
	struct queue_node *head;
	struct queue_node *tail;
	bool closed;
	size_t count;
	size_t cap; // 0 = unbounded
	pthread_mutex_t lock;
	pthread_cond_t not_empty_or_closed;
	void (*release_parent)(struct queue_node *);
	void (*retain_parent)(struct queue_node *);
};

#ifdef __cplusplus
extern "C" {
#endif

struct queue *create_q(void (*release_parent)(struct queue_node *),
		       void (*retain_parent)(struct queue_node *),
		       size_t cap);
void destroy_q(struct queue *q);
struct queue_node *close_q(struct queue *q);
bool push_q(struct queue *q, struct queue_node *n);
bool q_full(struct queue *q);
struct queue_node *pop_q(struct queue *q);
struct queue_node *pop_q_blocking(struct queue *q);
struct queue_node *peek_q(struct queue *q);

#ifdef __cplusplus
}
#endif
