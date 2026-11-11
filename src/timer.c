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
	if (heap == NULL) {
		pthread_mutex_unlock(&mgr->lock);
		return;
	}
	uint64_t now = now_ms();

	while (heap->count > 0) {
		struct heap_node *n = heap_peek(heap);
		if (n->priority > now)
			break;

		struct timer *t = CONTAINER_OF(heap_pop(heap), struct timer, node);
		pthread_mutex_unlock(&mgr->lock);
		t->callback(t->args);
		t->release(t->args);
		pthread_mutex_lock(&mgr->lock);
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

// switch to enum return type if caller should care about already running vs failures
static bool arm_timer(struct timer_manager *mgr,
		      struct timer *timer,
		      uint64_t delay_ms,
		      bool restart_allowed)
{
	pthread_mutex_lock(&mgr->lock);
	if (!restart_allowed && timer->node.index != NODE_NOT_IN_HEAP) {
		pthread_mutex_unlock(&mgr->lock);
		return false;
	}

	struct min_heap *h = mgr->timer_heap;
	if (h == NULL) {
		pthread_mutex_unlock(&mgr->lock);
		return false;
	}

	uint64_t expiry = now_ms() + delay_ms;

	struct heap_node *min = heap_peek(h);
	bool wake = (min == NULL) || (expiry < min->priority);

	if (timer->node.index == NODE_NOT_IN_HEAP) {
		if (!heap_push(h, &timer->node, expiry)) {
			pthread_mutex_unlock(&mgr->lock);
			return false;
		} else {
			timer->retain(timer->args);
		}
	} else
		heap_update(h, &timer->node, expiry);

	// newly added timer is first of the heap to time out => trigger polling return to update
	if (wake) {
		uint64_t x = 1;
		printf("writing to evend fd \n");
		write(mgr->event_fd, &x, sizeof(x));
	}

	pthread_mutex_unlock(&mgr->lock);
	return true;
}

bool start_timer(struct timer_manager *mgr, struct timer *t, uint64_t delay_ms)
{
	return arm_timer(mgr, t, delay_ms, true);
}

bool start_timer_if_idle(struct timer_manager *mgr, struct timer *t, uint64_t delay_ms)
{
	return arm_timer(mgr, t, delay_ms, false);
}

struct timer *create_timer_tcp_conn(void (*callback)(void *), struct tcp_ipv4_conn *conn, void (*retain)(void *), void (*release)(void *))
{
	return create_timer_internal(callback, conn, retain, release);
}

struct timer *create_timer(void (*callback)(void *), void *args)
{
	return create_timer_internal(callback, args, NULL, NULL);
}

static struct timer *create_timer_internal(void (*callback)(void *), void *args, void *retain, void *release)
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
static int get_timeout_locked(struct timer_manager *mgr)
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

int get_timeout(struct timer_manager *mgr)
{
	pthread_mutex_lock(&mgr->lock);
	int r = get_timeout_locked(mgr);
	pthread_mutex_unlock(&mgr->lock);
	return r;
}

void cancel_timer(struct timer_manager *mgr, struct timer *timer)
{
	if (!timer)
		return;
	pthread_mutex_lock(&mgr->lock);
	struct min_heap *h = mgr->timer_heap;
	if (heap_remove(h, &timer->node))
		timer->release(timer->args);

	pthread_mutex_unlock(&mgr->lock);
}
