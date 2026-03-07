#include "timer.h"
#include "container_of.h"

void execute_exp_timers(struct timer_manager *mgr)
{
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
}

struct timer_manager *create_timer_manager()
{
	struct timer_manager *mgr = malloc(sizeof(struct timer_manager));
	if (!mgr)
		return NULL;

	mgr->timer_heap = heap_create(HEAP_SIZE_DEFAULT);
	if (!mgr->timer_heap) {
		free(mgr);
		return NULL;
	}

	int fd = eventfd(0, EFD_NONBLOCK);
	if (fd < 0) {
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
	struct min_heap *h = mgr->timer_heap;
	if (h == NULL)
		return false;

	uint32_t expiry = now_ms() + delay_ms;
	if (timer->node.index == NODE_NOT_IN_HEAP) {
		if (!heap_push(h, &timer->node, expiry))
			return false;
	} else
		heap_update(h, &timer->node, expiry);

	// newly added timer is first of the heap to time out => trigger polling return to update
	if ((uint32_t)get_timeout(mgr) > expiry) {
		uint64_t x = 1;
		write(mgr->event_fd, &x, sizeof(x));
	}
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
	struct min_heap *h = mgr->timer_heap;
	heap_remove(h, &timer->node);
}
