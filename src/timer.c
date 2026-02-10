#include "timer.h"

void run_timers(struct timer_min_heap_t *heap)
{
    if (heap == NULL)
        return;
        
	uint64_t now = now_ms();

	while (heap->count > 0) {
		struct timer_t *t = peek_min_timer(heap);
		if (t->expires > now)
			break;

		t = pop_min_timer(heap);
		t->callback(t->args);
		free(t);
	}
}

struct timer_min_heap_t *create_timers_min_heap()
{
	struct timer_min_heap_t *timers = malloc(sizeof(struct timer_min_heap_t));
	if (timers == NULL)
		return NULL;

	timers->count = 0;
	return timers;
}

bool run_new_timer(struct timer_min_heap_t *heap,
		   uint64_t duration_ms,
		   void (*callback)(void *),
		   void *args)
{
	if (heap == NULL)
		return false;

	struct timer_t *timer = create_timer(duration_ms, callback, args);
	if (timer == NULL)
		return false;

	if (!add_timer(heap, timer)) {
		free(timer);
		return false;
	}
	return true;
}

struct timer_t *create_timer(uint64_t duration_ms, void (*callback)(void *), void *args)
{
	struct timer_t *timer = malloc(sizeof(struct timer_t));
	if (timer == NULL)
		return NULL;

	timer->expires = now_ms() + duration_ms;
	timer->callback = callback;
	timer->args = args;
	return timer;
}

// append and heapify up
bool add_timer(struct timer_min_heap_t *heap, struct timer_t *timer)
{
	if (heap->count >= HEAP_SIZE)
		return false;

	timer->heap_index = heap->count;
	heap->arr[heap->count++] = timer;
	heapify_up(heap, timer->heap_index);
	return true;
}

// remove min element, move last to root, heapify down
struct timer_t *pop_min_timer(struct timer_min_heap_t *heap)
{
	if (heap->count == 0)
		return NULL;

	struct timer_t *result = heap->arr[0];
	if (--heap->count > 0) {
		heap->arr[0] = heap->arr[heap->count];
		heap->arr[0]->heap_index = 0;
		heapify_down(heap, 0);
	}

	return result;
}

void heapify_up(struct timer_min_heap_t *heap, uint16_t i)
{
	struct timer_t *timer = heap->arr[i];

	uint16_t parent = (i - 1) / 2;
	while (i > 0 && timer->expires < heap->arr[parent]->expires) {
		heap->arr[i] = heap->arr[parent];
		heap->arr[i]->heap_index = i;
		i = parent;
		parent = (parent - 1) / 2;
	}
	heap->arr[i] = timer;
	timer->heap_index = i;
}

void heapify_down(struct timer_min_heap_t *heap, uint16_t i)
{
	struct timer_t *timer = heap->arr[i];

	while (((2 * i) + 1) < heap->count) {
		uint16_t left = 2 * i + 1;
		uint16_t right = 2 * i + 2;

		uint16_t smallest = left;
		if (right < heap->count && heap->arr[right]->expires < heap->arr[left]->expires)
			smallest = right;

		if (heap->arr[smallest]->expires >= timer->expires)
			break;

		heap->arr[i] = heap->arr[smallest];
		heap->arr[i]->heap_index = i;
		i = smallest;
	}

	heap->arr[i] = timer;
	timer->heap_index = i;
}

struct timer_t *peek_min_timer(struct timer_min_heap_t *heap)
{
	if (heap->count == 0)
		return NULL;
	return heap->arr[0];
}

void cancel_timer(struct timer_min_heap_t *heap, struct timer_t *timer)
{
	int i = timer->heap_index;
	int last = --heap->count;

	if (i == last)
		return; // removed last item, no heapify needed

	heap->arr[i] = heap->arr[last];
	heap->arr[i]->heap_index = i;
	if (i > 0) {
		int parent = (i - 1) / 2;
		if (heap->arr[i]->expires < heap->arr[parent]->expires) {
			heapify_up(heap, i);
			return;
		}
	}
	heapify_down(heap, i);
}

uint64_t now_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}