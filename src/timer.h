#pragma once
#include "types.h"
#include <limits.h>
#include <stdbool.h>
#include <sys/eventfd.h>
#include <unistd.h>

#define HEAP_SIZE (1 << 16) - 1

void execute_exp_timers(struct timer_min_heap_t *heap);
struct timer_min_heap_t *create_timers_min_heap(int wake_fd);
struct timer_t *create_timer(uint64_t duration_ms, void (*callback)(void *), void *args);
bool run_new_timer(struct timer_min_heap_t *heap,
		   uint64_t duration_ms,
		   void (*callback)(void *),
		   void *args);
bool add_timer(struct timer_min_heap_t *heap, struct timer_t *timer);
struct timer_t *pop_min_timer(struct timer_min_heap_t *heap);
struct timer_t *peek_min_timer(struct timer_min_heap_t *heap);
void heapify_down(struct timer_min_heap_t *heap, uint16_t i);
void heapify_up(struct timer_min_heap_t *heap, uint16_t i);
void cancel_timer(struct timer_min_heap_t *heap, struct timer_t *timer);
int get_timeout(struct timer_min_heap_t *heap);
uint64_t now_ms(void);

struct timer_t {
	uint64_t expires;
	void (*callback)(void *);
	void *args;
	uint16_t heap_index;
};

struct timer_min_heap_t {
	struct timer_t *arr[HEAP_SIZE];
	uint16_t count;
	int wake_fd;
};
