#pragma once
#include "heap.h"
#include <stdbool.h>

struct timer {
	void (*callback)(void *);
	void *args;
	struct heap_node node; // expiry time is stored in node priority
};

struct timer_manager {
	struct min_heap *timer_heap;
	int event_fd; // written to when new timer added, wake and check min timer again
};

#ifdef __cplusplus
extern "C" {
#endif

struct timer *create_timer(void (*callback)(void *), void *args);

void execute_exp_timers(struct timer_manager *mgr);
struct timer_manager *create_timer_manager();
bool start_timer(struct timer_manager *mgr, struct timer *timer, uint64_t duration_ms);
void cancel_timer(struct timer_manager *mgr, struct timer *timer);
int get_timeout(struct timer_manager *mgr);

#ifdef __cplusplus
}
#endif
