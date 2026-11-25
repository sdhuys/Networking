#pragma once
// Runs a blocking stack call (accept, receive, connect, ...) on its own thread and waits
// for it with a timeout, so a stack bug fails the test instead of hanging the suite.
// A call that times out is left running on its detached thread.

#include <chrono>
#include <functional>
#include <future>
#include <memory>
#include <optional>
#include <thread>

template <typename T> class Pending
{
      public:
	explicit Pending(std::function<T()> fn)
	{
		auto p = std::make_shared<std::promise<T>>();
		fut_ = p->get_future();
		std::thread([p, fn = std::move(fn)]() { p->set_value(fn()); }).detach();
	}
	// waits up to `ms`; nullopt if the call is still blocked
	std::optional<T> wait(int ms)
	{
		if (!fut_.valid())
			return result_;
		if (fut_.wait_for(std::chrono::milliseconds(ms)) != std::future_status::ready)
			return std::nullopt;
		result_ = fut_.get();
		return result_;
	}
	bool done()
	{
		return wait(0).has_value();
	}

      private:
	std::future<T> fut_;
	std::optional<T> result_;
};

template <typename T> std::optional<T> call_with_timeout(std::function<T()> fn, int ms)
{
	Pending<T> p(std::move(fn));
	return p.wait(ms);
}
