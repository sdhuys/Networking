// The timer manager on its own, with the fake clock: arming, cancelling, re-arming, the
// reference counting of owned timers, and timer_should_execute(), the check a callback
// uses to tell a current firing from one that was cancelled or re-armed after it was
// popped (finding 19).

#include "fake_env.h"
extern "C" {
#include "heap.h" // heap_destroy; has no extern "C" of its own
}
#include "timer.h"

#include <gtest/gtest.h>

#include <cstdlib>
#include <unistd.h>

namespace
{
struct Counters {
	int fired = 0;
	int retained = 0;
	int released = 0;
	struct timer_manager *mgr = nullptr;
	struct timer *self = nullptr;
	bool rearm = false;
	bool claimed = false;
};

void on_fire(void *arg)
{
	auto *c = static_cast<Counters *>(arg);
	c->fired++;
	if (c->self)
		c->claimed = timer_should_execute(c->mgr, c->self);
	if (c->rearm) {
		c->rearm = false;
		start_timer(c->mgr, c->self, 100);
	}
}
void on_retain(void *arg)
{
	static_cast<Counters *>(arg)->retained++;
}
void on_release(void *arg)
{
	static_cast<Counters *>(arg)->released++;
}
} // namespace

class Timer : public ::testing::Test
{
      protected:
	struct timer_manager *mgr = nullptr;
	Counters c;
	struct timer *t = nullptr;

	void SetUp() override
	{
		mgr = create_timer_manager();
		ASSERT_NE(mgr, nullptr);
		c.mgr = mgr;
		t = create_timer_owned(on_fire, &c, on_retain, on_release);
		ASSERT_NE(t, nullptr);
	}
	void TearDown() override
	{
		cancel_timer(mgr, t); // whatever the test left armed
		EXPECT_EQ(c.retained, c.released) << "owned timer references don't balance";
		free(t);
		// timer_manager has no destroy function: free what create_timer_manager made
		heap_destroy(mgr->timer_heap);
		close(mgr->event_fd);
		pthread_mutex_destroy(&mgr->lock);
		free(mgr);
	}
	void run_at(uint64_t ms)
	{
		fake_clock_advance(ms);
		execute_exp_timers(mgr);
	}
};

TEST_F(Timer, FiresOnceAtItsDeadline)
{
	ASSERT_TRUE(start_timer(mgr, t, 100));
	run_at(99);
	EXPECT_EQ(c.fired, 0);
	run_at(1);
	EXPECT_EQ(c.fired, 1);
	run_at(1000);
	EXPECT_EQ(c.fired, 1) << "a timer fires once per arming";
}

TEST_F(Timer, CancelledTimerDoesNotFire)
{
	start_timer(mgr, t, 100);
	cancel_timer(mgr, t);
	run_at(200);
	EXPECT_EQ(c.fired, 0);
	EXPECT_EQ(c.retained, 1);
	EXPECT_EQ(c.released, 1) << "cancelling drops the armed timer's reference";
}

TEST_F(Timer, RestartMovesTheDeadlineWithoutASecondReference)
{
	start_timer(mgr, t, 100);
	start_timer(mgr, t, 300); // re-arm while armed
	EXPECT_EQ(c.retained, 1) << "re-arming an armed timer must not retain twice";
	run_at(200);
	EXPECT_EQ(c.fired, 0) << "the old deadline no longer applies";
	run_at(100);
	EXPECT_EQ(c.fired, 1);
	EXPECT_EQ(c.released, 1);
}

TEST_F(Timer, StartIfIdleLeavesAnArmedTimerAlone)
{
	start_timer(mgr, t, 100);
	EXPECT_FALSE(start_timer_if_idle(mgr, t, 10));
	run_at(10);
	EXPECT_EQ(c.fired, 0) << "start_timer_if_idle must not move an armed timer";
	run_at(90);
	EXPECT_EQ(c.fired, 1);
	EXPECT_TRUE(start_timer_if_idle(mgr, t, 10)) << "idle again after firing";
	run_at(10);
	EXPECT_EQ(c.fired, 2);
}

TEST_F(Timer, CallbackCanRearmItsOwnTimer)
{
	c.self = t;
	c.rearm = true;
	start_timer(mgr, t, 100);
	run_at(100);
	EXPECT_EQ(c.fired, 1);
	run_at(100);
	EXPECT_EQ(c.fired, 2);
	EXPECT_EQ(c.retained, 2);
	EXPECT_EQ(c.released, 2);
}

// ---- timer_should_execute: the claim a callback makes before acting ----

TEST_F(Timer, ACurrentFiringCanBeClaimedOnce)
{
	c.self = t;
	start_timer(mgr, t, 100);
	run_at(100);
	ASSERT_EQ(c.fired, 1);
	EXPECT_TRUE(c.claimed) << "an untouched firing is current";
	EXPECT_FALSE(timer_should_execute(mgr, t)) << "claiming consumes the firing";
}

TEST_F(Timer, CancelAfterExpiryMakesTheClaimFail)
{
	// the case cancel_timer can't stop: the timer has expired (and may already be
	// popped) when it is cancelled. Here the claim is made directly, as the callback would.
	start_timer(mgr, t, 100);
	fake_clock_advance(100);
	cancel_timer(mgr, t);
	EXPECT_FALSE(timer_should_execute(mgr, t))
	    << "cancel must clear the deadline even when the timer can't be removed from the heap";
}

TEST_F(Timer, RearmAfterExpiryMakesTheOldFiringStale)
{
	start_timer(mgr, t, 100);
	fake_clock_advance(100);
	start_timer(mgr, t, 500); // e.g. an ACK restarted the RTO just after it expired
	EXPECT_FALSE(timer_should_execute(mgr, t)) << "the deadline is now in the future";
	fake_clock_advance(500);
	EXPECT_TRUE(timer_should_execute(mgr, t));
	execute_exp_timers(mgr); // let the manager pop it and drop its reference
}

TEST_F(Timer, NeverArmedTimerCannotBeClaimed)
{
	EXPECT_FALSE(timer_should_execute(mgr, t));
}

TEST_F(Timer, ManyTimersFireInDeadlineOrder)
{
	struct Order {
		int *next;
		int id;
		int got = -1;
	};
	int next = 0;
	std::vector<Order> o(5);
	std::vector<struct timer *> ts;
	auto cb = [](void *a) {
		auto *x = static_cast<Order *>(a);
		x->got = (*x->next)++;
	};
	const uint64_t delays[5] = {50, 10, 40, 20, 30};
	for (int i = 0; i < 5; i++) {
		o[i].next = &next;
		o[i].id = i;
		ts.push_back(create_timer(cb, &o[i]));
		start_timer(mgr, ts.back(), delays[i]);
	}
	run_at(100);
	EXPECT_EQ(o[1].got, 0);
	EXPECT_EQ(o[3].got, 1);
	EXPECT_EQ(o[4].got, 2);
	EXPECT_EQ(o[2].got, 3);
	EXPECT_EQ(o[0].got, 4);
	for (auto *x : ts)
		free(x);
}
