#pragma once
#include "heap.h"
#include <pthread.h>
#include <stdbool.h>

struct timer {
	void (*callback)(void *);
	void (*retain)(void *); // to retain conn when timer needs a ref to it, can be null (for ARP
				// sweep timer for instance)
	void (*release)(void *); // to release conn when timer is done with ref, can be null (for
				 // ARP sweep timer for instance)
	void *args;
	struct heap_node node; // expiry time is stored in node priority
};

struct timer_manager {
	struct min_heap *timer_heap;
	int event_fd; // written to when new timer added, wake and check min timer again
	pthread_mutex_t lock;
};

#ifdef __cplusplus
extern "C" {
#endif

struct timer *create_timer(void (*callback)(void *), void *args);
struct timer *create_timer_owned(void (*callback)(void *),
				 void *conn,
				 void (*retain)(void *),
				 void (*release)(void *));

void execute_exp_timers(struct timer_manager *mgr);
struct timer_manager *create_timer_manager();
bool start_timer(struct timer_manager *mgr, struct timer *timer, uint64_t delay_ms);
bool start_timer_if_idle(struct timer_manager *mgr, struct timer *timer, uint64_t delay_ms);
void cancel_timer(struct timer_manager *mgr, struct timer *timer);
int get_timeout(struct timer_manager *mgr);

#ifdef __cplusplus
}
#endif
