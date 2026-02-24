#pragma once
#include "heap.h"
#include "types.h"
#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/eventfd.h>
#include <unistd.h>

struct timer *create_timer(void (*callback)(void *), void *args);

void execute_exp_timers(struct timer_manager *mgr);
struct timer_manager *create_timer_manager();
bool start_timer(struct timer_manager *mgr, struct timer *timer, uint64_t duration_ms);
void cancel_timer(struct timer_manager *mgr, struct timer *timer);
int get_timeout(struct timer_manager *mgr);

uint64_t now_ms();
uint64_t now_s();

struct timer {
	void (*callback)(void *);
	void *args;
	struct heap_node node; // expiry time is stored in node priority
};

struct timer_manager {
	struct min_heap *timer_heap;
	int event_fd; // written to when new timer added, wake and check min timer again
};