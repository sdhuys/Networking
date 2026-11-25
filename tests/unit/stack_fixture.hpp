#pragma once
// Unit-test fixture: one stack, no threads, fake clock. The test plays the remote peer:
// it injects frames, pumps the TX worker and timers by hand, and checks every frame the
// stack sends.

#include "blocking.hpp"
#include "fake_env.h"
#include "harness.h"
#include "wire.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <deque>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using namespace wire;

// A connection as the test's peer sees it.
struct PeerConn {
	uint16_t stack_port = 0; // port on the stack
	uint16_t peer_port = 0;	 // port on the (fake) peer
	uint32_t peer_iss = 0;
	uint32_t peer_nxt = 0; // next sequence number the peer sends
	uint32_t stack_iss = 0;
	uint32_t stack_nxt = 0; // next sequence number the peer expects from the stack
	uint16_t peer_window = 65535;
	bool ts = false;	// timestamps negotiated
	uint32_t ts_recent = 0; // last TSval the stack sent (echoed as TSecr)
	bool sack = false;
	uint8_t stack_wscale = 0; // scale the stack announced (for its window field)
	int fd = -1;		  // stack-side socket
};

class StackTest : public ::testing::Test
{
      protected:
	static constexpr const char *STACK_IP = "10.0.0.2";
	static constexpr const char *PEER_IP = "10.0.0.1";
	const Mac stack_mac{0x02, 0, 0, 0, 0, 0x02};
	const Mac peer_mac{0x02, 0, 0, 0, 0, 0x01};

	th_stack *st = nullptr;
	int pool_baseline = 0;
	bool check_pool_leaks = true;

	void SetUp() override
	{
		th_global_init();
		fake_set_drop_percent(0);
		pool_baseline = th_pool_free_count();
		st = th_stack_create(STACK_IP, stack_mac.data(), &StackTest::on_tx, this);
		th_stack_add_arp(st, PEER_IP, peer_mac.data());
	}

	void TearDown() override
	{
		if (!check_pool_leaks || HasFailure() || stack_hung_)
			return; // a failed test may legitimately leave packets behind
		// Packets a test still holds are its own business, but everything the stack
		// took from the pool for a finished exchange must be back.
		{
			std::lock_guard<std::mutex> g(out_mu_);
			out_.clear();
		}
		int now = th_pool_free_count();
		EXPECT_EQ(now, pool_baseline)
		    << "packet pool: " << (pool_baseline - now)
		    << " packet(s) not returned (a retain without a matching release)";
	}

	// ---------- running stack code with a deadlock guard ----------
	// Stack code runs on a helper thread. If it doesn't return within 2 s the stack is
	// deadlocked (or spinning): the test fails with a message instead of hanging the suite.
	template <typename F> auto guarded(const std::string &what, F fn) -> decltype(fn())
	{
		using R = decltype(fn());
		Pending<R> p(std::function<R()>(std::move(fn)));
		auto r = p.wait(2000);
		if (!r) {
			stack_hung_ = true;
			throw std::runtime_error(
			    "stack did not return within 2 s while " + what +
			    " (deadlock?). Check the thread backtraces in a debugger.");
		}
		return *r;
	}
	size_t pump()
	{
		return guarded("running the TX worker", [this] { return th_pump_tx(st); });
	}

	// ---------- frames out of the stack ----------
	static void on_tx(void *user, const uint8_t *frame, size_t len)
	{
		auto *self = static_cast<StackTest *>(user);
		std::lock_guard<std::mutex> g(self->out_mu_);
		self->out_.emplace_back(frame, frame + len);
	}

	size_t pending_frames()
	{
		std::lock_guard<std::mutex> g(out_mu_);
		return out_.size();
	}

	// Runs the TX worker, then returns the next TCP segment the stack sent.
	// Every segment is checked for well-formedness on the way out.
	TcpSegment next_out(const std::string &what = "a segment")
	{
		pump();
		std::vector<uint8_t> f;
		{
			std::lock_guard<std::mutex> g(out_mu_);
			while (!out_.empty() && ethertype(out_.front()) != 0x0800)
				out_.pop_front(); // ARP is not expected here; skip it
			if (out_.empty())
				throw std::runtime_error("expected " + what +
							 " from the stack, got nothing");
			f = std::move(out_.front());
			out_.pop_front();
		}
		auto s = parse(f);
		if (!s)
			throw std::runtime_error("stack sent a frame that is not IPv4/TCP");
		check_well_formed(*s);
		return *s;
	}

	// All segments currently queued, after pumping TX.
	std::vector<TcpSegment> drain_out()
	{
		std::vector<TcpSegment> v;
		while (true) {
			pump();
			{
				std::lock_guard<std::mutex> g(out_mu_);
				if (out_.empty())
					break;
			}
			v.push_back(next_out());
		}
		return v;
	}

	// Every frame queued so far, raw (any ethertype or protocol), after pumping TX.
	std::vector<std::vector<uint8_t>> take_raw_frames()
	{
		pump();
		std::lock_guard<std::mutex> g(out_mu_);
		std::vector<std::vector<uint8_t>> v(out_.begin(), out_.end());
		out_.clear();
		return v;
	}

	void expect_nothing_out(const std::string &why)
	{
		pump();
		std::lock_guard<std::mutex> g(out_mu_);
		if (!out_.empty()) {
			auto s = parse(out_.front());
			ADD_FAILURE() << "expected no segment (" << why << "), but the stack sent "
				      << (s ? s->describe() : std::string("a non-TCP frame"));
		}
	}

	static void check_well_formed(const TcpSegment &s)
	{
		std::string d = s.describe();
		EXPECT_TRUE(s.ip_checksum_ok) << "bad IPv4 checksum: " << d;
		EXPECT_TRUE(s.tcp_checksum_ok) << "bad TCP checksum: " << d;
		EXPECT_TRUE(s.options_well_formed) << "malformed TCP options: " << d;
		EXPECT_LE(s.options_len, 40u) << "options area over 40 bytes: " << d;
		EXPECT_EQ((size_t)s.data_offset * 4, 20 + s.options_len) << d;
		EXPECT_LE(s.frame_len, 1514u) << "frame larger than the Ethernet MTU: " << d;
		EXPECT_EQ((size_t)s.ip_total_length + 14, s.frame_len)
		    << "IP length vs frame: " << d;
		EXPECT_TRUE(s.dont_fragment) << d;
	}

	// ---------- frames into the stack ----------
	TcpSegment seg_for(const PeerConn &c, uint8_t flags)
	{
		TcpSegment s;
		s.src_mac = peer_mac;
		s.dst_mac = stack_mac;
		s.src_ip = ip(PEER_IP);
		s.dst_ip = ip(STACK_IP);
		s.src_port = c.peer_port;
		s.dst_port = c.stack_port;
		s.seq = c.peer_nxt;
		s.ack = (flags & ACK) ? c.stack_nxt : 0;
		s.flags = flags;
		s.window = c.peer_window;
		if (c.ts)
			s.opts.ts = std::make_pair((uint32_t)fake_clock_ms(), c.ts_recent);
		return s;
	}

	int inject(const TcpSegment &s)
	{
		std::vector<uint8_t> f = build(s);
		return guarded("processing " + s.describe(),
			       [this, f] { return th_inject(st, f.data(), f.size()); });
	}

	// Sends a segment from the peer and advances the peer's sequence number.
	int peer_send(PeerConn &c, uint8_t flags, const std::vector<uint8_t> &payload = {})
	{
		TcpSegment s = seg_for(c, flags);
		s.payload = payload;
		int r = inject(s);
		c.peer_nxt += s.seq_len();
		return r;
	}

	// Updates the peer's view from a segment the stack sent.
	void peer_saw(PeerConn &c, const TcpSegment &s)
	{
		if (s.opts.ts)
			c.ts_recent = s.opts.ts->first;
		uint32_t end = s.seq + s.seq_len();
		if (seq_lt(c.stack_nxt, end) && seq_le(s.seq, c.stack_nxt))
			c.stack_nxt = end;
	}

	// ---------- time ----------
	// Moves the fake clock forward in small steps, running timers and the TX worker
	// at each step, like the real threads would.
	void advance(uint64_t ms, uint64_t step = 10)
	{
		uint64_t done = 0;
		while (done < ms) {
			uint64_t d = std::min(step, ms - done);
			fake_clock_advance(d);
			done += d;
			guarded("running timers at t+" + std::to_string(done) + " ms", [this] {
				th_run_timers(st);
				th_pump_tx(st);
				return 0;
			});
		}
	}

	// ---------- connection setup ----------
	static TcpOptions linux_syn_options()
	{
		TcpOptions o;
		o.mss = 1460;
		o.sack_permitted = true;
		o.ts = std::make_pair((uint32_t)fake_clock_ms(), 0u);
		o.wscale = 7;
		return o;
	}

	int listen(uint16_t port)
	{
		int fd = th_listen(st, port);
		if (fd < 0)
			throw std::runtime_error("open_listener failed: " + std::to_string(fd));
		return fd;
	}

	// Peer connects to a listening port. Leaves the connection ESTABLISHED and accepted.
	PeerConn open_passive(int listen_fd,
			      uint16_t port,
			      uint16_t peer_port,
			      TcpOptions syn_opts = linux_syn_options(),
			      uint32_t peer_iss = 1000)
	{
		PeerConn c;
		c.stack_port = port;
		c.peer_port = peer_port;
		c.peer_iss = c.peer_nxt = peer_iss;

		TcpSegment syn = seg_for(c, SYN);
		syn.opts = syn_opts;
		inject(syn);
		c.peer_nxt += 1;

		TcpSegment sa = next_out("SYN-ACK");
		if (sa.flags != (SYN | ACK))
			throw std::runtime_error("expected SYN-ACK, got " + sa.describe());
		c.stack_iss = sa.seq;
		c.stack_nxt = sa.seq + 1;
		c.ts = syn_opts.ts.has_value() && sa.opts.ts.has_value();
		c.sack = syn_opts.sack_permitted && sa.opts.sack_permitted;
		c.stack_wscale = sa.opts.wscale.value_or(0);
		peer_saw(c, sa);

		peer_send(c, ACK);
		auto fd = call_with_timeout<int>(
		    [this, listen_fd] { return th_accept(st, listen_fd); }, 2000);
		if (!fd || *fd < 0)
			throw std::runtime_error("accept did not return a connection");
		c.fd = *fd;
		return c;
	}

	// Stack connects out to the peer. Leaves the connection ESTABLISHED.
	PeerConn open_active(uint16_t local_port,
			     uint16_t peer_port,
			     TcpOptions synack_opts = linux_syn_options(),
			     uint32_t peer_iss = 5000)
	{
		PeerConn c;
		c.stack_port = local_port;
		c.peer_port = peer_port;
		c.peer_iss = c.peer_nxt = peer_iss;

		Pending<int> connect([this, local_port, peer_port] {
			return th_connect(st, local_port, PEER_IP, peer_port);
		});
		TcpSegment syn = wait_out("SYN");
		if (syn.flags != SYN)
			throw std::runtime_error("expected SYN, got " + syn.describe());
		c.stack_iss = syn.seq;
		c.stack_nxt = syn.seq + 1;
		peer_saw(c, syn);

		TcpSegment sa = seg_for(c, SYN | ACK);
		sa.opts = synack_opts;
		if (sa.opts.ts && syn.opts.ts)
			sa.opts.ts->second = syn.opts.ts->first;
		inject(sa);
		c.peer_nxt += 1;
		c.ts = synack_opts.ts.has_value() && syn.opts.ts.has_value();
		c.sack = synack_opts.sack_permitted && syn.opts.sack_permitted;
		c.stack_wscale = syn.opts.wscale.value_or(0);

		auto fd = connect.wait(2000);
		if (!fd || *fd < 0)
			throw std::runtime_error("tcp_connect did not return a connection");
		c.fd = *fd;
		return c;
	}

	// Waits for a segment produced by another thread (e.g. tcp_connect).
	TcpSegment wait_out(const std::string &what, int ms = 2000)
	{
		for (int i = 0; i < ms; i++) {
			pump();
			if (pending_frames() > 0)
				return next_out(what);
			std::this_thread::sleep_for(std::chrono::milliseconds(1));
		}
		throw std::runtime_error("expected " + what + " from the stack, got nothing");
	}

	th_conn_info info(const PeerConn &c)
	{
		th_conn_info i{};
		if (!th_conn_lookup(st, c.stack_port, PEER_IP, c.peer_port, &i))
			i.state = -1;
		return i;
	}
	bool exists(const PeerConn &c)
	{
		th_conn_info i{};
		return th_conn_lookup(st, c.stack_port, PEER_IP, c.peer_port, &i);
	}

	// App-side helpers with timeouts
	std::vector<uint8_t> app_read(const PeerConn &c, size_t n, int ms = 2000)
	{
		std::vector<uint8_t> got;
		while (got.size() < n) {
			std::vector<uint8_t> buf(n - got.size());
			int fd = c.fd;
			auto r = call_with_timeout<long>(
			    [this, fd, &buf] { return th_recv(st, fd, buf.data(), buf.size()); },
			    ms);
			if (!r)
				throw std::runtime_error("receive() blocked: wanted " +
							 std::to_string(n) + " bytes, had " +
							 std::to_string(got.size()));
			if (*r <= 0)
				throw std::runtime_error("receive() returned " +
							 std::to_string(*r) + " after " +
							 std::to_string(got.size()) + " bytes");
			got.insert(got.end(), buf.begin(), buf.begin() + *r);
		}
		return got;
	}

	void app_write(const PeerConn &c, const std::vector<uint8_t> &data)
	{
		int fd = c.fd;
		auto r = call_with_timeout<long>(
		    [this, fd, data] { return th_send(st, fd, data.data(), data.size()); }, 2000);
		if (!r || *r != (long)data.size())
			throw std::runtime_error("send_down did not take all the data");
	}

	static std::vector<uint8_t> pattern(size_t n, uint32_t seed = 1)
	{
		std::vector<uint8_t> v(n);
		uint32_t x = seed * 2654435761u + 1;
		for (auto &b : v) {
			x ^= x << 13;
			x ^= x >> 17;
			x ^= x << 5;
			b = (uint8_t)x;
		}
		return v;
	}

      private:
	bool stack_hung_ = false;
	std::mutex out_mu_;
	std::deque<std::vector<uint8_t>> out_;
};
