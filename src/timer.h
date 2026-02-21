#pragma once
#include "types.h"
#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/eventfd.h>
#include <unistd.h>

#define HEAP_SIZE (1 << 16) - 1

void execute_exp_timers(struct timer_min_heap *heap);
struct timer_min_heap *create_timers_min_heap(int wake_fd);
struct timer *create_timer(uint64_t duration_ms, void (*callback)(void *), void *args);
bool run_new_timer(struct timer_min_heap *heap,
		   uint64_t duration_ms,
		   void (*callback)(void *),
		   void *args);
bool add_timer(struct timer_min_heap *heap, struct timer *timer);
struct timer *pop_min_timer(struct timer_min_heap *heap);
struct timer *peek_min_timer(struct timer_min_heap *heap);
void heapify_down(struct timer_min_heap *heap, uint16_t i);
void heapify_up(struct timer_min_heap *heap, uint16_t i);
void cancel_timer(struct timer_min_heap *heap, struct timer *timer);
int get_timeout(struct timer_min_heap *heap);
uint64_t now_ms();
uint64_t now_s();

struct timer {
	uint64_t expires;
	void (*callback)(void *);
	void *args;
	uint16_t heap_index;
};

struct timer_min_heap {
	struct timer *arr[HEAP_SIZE];
	uint16_t count;
	int wake_fd;
};
