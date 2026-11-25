#pragma once
// A simulated Ethernet link between two stacks running on their real threads.
// Frames can be dropped, duplicated, delayed and reordered. Each direction has its own
// impairments and counters.

#include "harness.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <queue>
#include <random>
#include <thread>
#include <vector>

struct Impairments {
	double loss = 0;      // probability a frame is dropped
	double duplicate = 0; // probability a frame is delivered twice
	double reorder = 0;   // probability a frame gets extra delay so later frames overtake it
	int delay_ms = 0;     // base one-way delay
	int jitter_ms = 0;    // uniform extra delay 0..jitter
	int reorder_extra_ms = 20;
};

struct LinkStats {
	std::atomic<uint64_t> sent{0}, dropped{0}, duplicated{0}, reordered{0}, ingress_full{0};
};

class Link
{
      public:
	// Stacks are created by the link, so it can install itself as their TX callback.
	Link(const char *ip_a, const char *ip_b, uint32_t seed = 1) : rng_(seed)
	{
		th_global_init();
		const uint8_t mac_a[6] = {0x02, 0, 0, 0, 0xA0, 0x0A};
		const uint8_t mac_b[6] = {0x02, 0, 0, 0, 0xB0, 0x0B};
		end_[0].owner = this;
		end_[0].dir = 0;
		end_[1].owner = this;
		end_[1].dir = 1;
		a = th_stack_create(ip_a, mac_a, &Link::on_tx, &end_[0]);
		b = th_stack_create(ip_b, mac_b, &Link::on_tx, &end_[1]);
		worker_ = std::thread([this] { run(); });
		worker_.detach();
	}

	// Never destroyed: stacks from finished tests keep running their threads and may
	// still send. A closed link drops everything.
	void close()
	{
		closed_ = true;
	}

	void start_stacks()
	{
		th_start_threads(a);
		th_start_threads(b);
	}

	void set(const Impairments &both)
	{
		imp_[0] = imp_[1] = both;
	}
	void set_a_to_b(const Impairments &i)
	{
		imp_[0] = i;
	}
	void set_b_to_a(const Impairments &i)
	{
		imp_[1] = i;
	}

	th_stack *a = nullptr;
	th_stack *b = nullptr;
	LinkStats stats[2]; // [0] = a->b, [1] = b->a

      private:
	struct End {
		Link *owner;
		int dir;
	};
	struct Item {
		std::chrono::steady_clock::time_point due;
		uint64_t order;
		int dir;
		std::vector<uint8_t> frame;
		bool operator>(const Item &o) const
		{
			return due != o.due ? due > o.due : order > o.order;
		}
	};

	static void on_tx(void *user, const uint8_t *f, size_t n)
	{
		End *e = static_cast<End *>(user);
		e->owner->enqueue(e->dir, f, n);
	}

	void enqueue(int dir, const uint8_t *f, size_t n)
	{
		if (closed_)
			return;
		std::lock_guard<std::mutex> g(mu_);
		const Impairments &im = imp_[dir];
		stats[dir].sent++;
		if (chance(im.loss)) {
			stats[dir].dropped++;
			return;
		}
		int copies = chance(im.duplicate) ? 2 : 1;
		if (copies == 2)
			stats[dir].duplicated++;
		for (int k = 0; k < copies; k++) {
			int ms =
			    im.delay_ms + (im.jitter_ms ? (int)(rng_() % (im.jitter_ms + 1)) : 0);
			if (chance(im.reorder)) {
				ms += im.reorder_extra_ms;
				stats[dir].reordered++;
			}
			Item it{std::chrono::steady_clock::now() + std::chrono::milliseconds(ms),
				order_++,
				dir,
				std::vector<uint8_t>(f, f + n)};
			q_.push(std::move(it));
		}
		cv_.notify_one();
	}

	bool chance(double p)
	{
		return p > 0 && std::uniform_real_distribution<double>(0, 1)(rng_) < p;
	}

	void run()
	{
		std::unique_lock<std::mutex> lk(mu_);
		for (;;) {
			if (q_.empty()) {
				cv_.wait(lk);
				continue;
			}
			auto due = q_.top().due;
			if (std::chrono::steady_clock::now() < due) {
				cv_.wait_until(lk, due);
				continue;
			}
			Item it = q_.top();
			q_.pop();
			lk.unlock();
			th_stack *to = it.dir == 0 ? b : a;
			if (!closed_ && !th_enqueue_ingress(to, it.frame.data(), it.frame.size()))
				stats[it.dir].ingress_full++;
			lk.lock();
		}
	}

	End end_[2];
	Impairments imp_[2];
	std::atomic<bool> closed_{false};
	std::mutex mu_;
	std::condition_variable cv_;
	std::priority_queue<Item, std::vector<Item>, std::greater<Item>> q_;
	uint64_t order_ = 0;
	std::mt19937 rng_;
	std::thread worker_;
};
