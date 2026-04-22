#include "timer_worker.h"
#include "stack.h"
#include "timer.h"
#include <poll.h>
#include <stdint.h>
#include <unistd.h>

void *start_timers_loop(void *arg)
{
	struct timer_manager *timer_mgr = ((struct stack *)arg)->timer_mgr;
	struct pollfd pfd = {.fd = timer_mgr->event_fd, .events = POLLIN};
	for (;;) {
		int timeout_ms = get_timeout(timer_mgr);
		if (timeout_ms == 0) {
			execute_exp_timers(timer_mgr);
			continue;
		}
		int poll_r = poll(&pfd, 1, timeout_ms);
		if (poll_r > 0 && pfd.events & POLLIN) {
			uint64_t x;
			read(pfd.fd, &x, sizeof(x)); // drain eventfd
		}
		execute_exp_timers(timer_mgr);
	}
    return NULL;
}