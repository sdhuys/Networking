#include "timer.h"
#include "container_of.h"
#include "time_now.h"
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/eventfd.h>
#include <time.h>
#include <unistd.h>

void execute_exp_timers(struct timer_manager *mgr)
{
	pthread_mutex_lock(&mgr->lock);
	struct min_heap *heap = mgr->timer_heap;
	if (heap == NULL)
		return;

	uint64_t now = now_ms();

	while (heap->count > 0) {
		struct heap_node *n = heap_peek(heap);
		if (n->priority > now)
			break;

		struct timer *t = CONTAINER_OF(heap_pop(heap), struct timer, node);
		t->callback(t->args);
		now = now_ms();
	}
	pthread_mutex_unlock(&mgr->lock);
}

struct timer_manager *create_timer_manager()
{
	struct timer_manager *mgr = malloc(sizeof(struct timer_manager));
	if (!mgr)
		return NULL;

	if (pthread_mutex_init(&mgr->lock, NULL) != 0) {
		free(mgr);
		return NULL;
	}

	mgr->timer_heap = heap_create(HEAP_SIZE_DEFAULT);
	if (!mgr->timer_heap) {
		pthread_mutex_destroy(&mgr->lock);
		free(mgr);
		return NULL;
	}

	int fd = eventfd(0, EFD_NONBLOCK);
	if (fd < 0) {
		pthread_mutex_destroy(&mgr->lock);
		heap_destroy(mgr->timer_heap);
		free(mgr);
		return NULL;
	}
	mgr->event_fd = fd;

	return mgr;
}

// (re)start
bool start_timer(struct timer_manager *mgr, struct timer *timer, uint64_t delay_ms)
{
	pthread_mutex_lock(&mgr->lock);

	struct min_heap *h = mgr->timer_heap;
	uint64_t curr_timeout = get_timeout(mgr);
	printf("\nCURRENT timeout: %lu \n", curr_timeout);
	printf("Adding new timer: timeout: %lu \n", delay_ms);
	if (h == NULL) {
		pthread_mutex_unlock(&mgr->lock);
		return false;
	}

	uint64_t expiry = now_ms() + delay_ms;
	if (timer->node.index == NODE_NOT_IN_HEAP) {
		if (!heap_push(h, &timer->node, expiry)) {
			pthread_mutex_unlock(&mgr->lock);
			return false;
		}
	} else
		heap_update(h, &timer->node, expiry);

	// newly added timer is first of the heap to time out => trigger polling return to update
	if (curr_timeout > expiry) {
		uint64_t x = 1;
		printf("writing to evend fd \n");
		write(mgr->event_fd, &x, sizeof(x));
	}

	pthread_mutex_unlock(&mgr->lock);
	return true;
}

struct timer *create_timer(void (*callback)(void *), void *args)
{
	struct timer *timer = malloc(sizeof(struct timer));
	if (timer == NULL)
		return NULL;

	timer->callback = callback;
	timer->args = args;
	timer->node.index = NODE_NOT_IN_HEAP;
	return timer;
}

// caller must hold lock
int get_timeout(struct timer_manager *mgr)
{
	struct min_heap *h = mgr->timer_heap;
	struct heap_node *n = heap_peek(h);
	if (!n)
		return -1; // infinite

	uint64_t now = now_ms();

	if (n->priority <= now)
		return 0;

	uint64_t delta = n->priority - now;

	if (delta > INT_MAX)
		return INT_MAX;

	return (int)delta;
}

void cancel_timer(struct timer_manager *mgr, struct timer *timer)
{
	if (!timer)
		return;
	pthread_mutex_lock(&mgr->lock);
	struct min_heap *h = mgr->timer_heap;
	heap_remove(h, &timer->node);
	pthread_mutex_unlock(&mgr->lock);
}
