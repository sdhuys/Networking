// Stack-to-stack tests: two stacks on their real RX, TX and timer threads, connected by a
// simulated link. Real clock, real concurrency. Run under ThreadSanitizer
// (-DSTACK_SANITIZE=thread) to check the locking.

#include "blocking.hpp"
#include "harness.h"
#include "link.hpp"

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

namespace
{

constexpr const char *IP_A = "10.1.0.2";
constexpr const char *IP_B = "10.1.0.3";

std::vector<uint8_t> pattern(size_t n, uint32_t seed)
{
	std::vector<uint8_t> v(n);
	uint32_t x = seed * 2654435761u + 7;
	for (auto &b : v) {
		x ^= x << 13;
		x ^= x >> 17;
		x ^= x << 5;
		b = (uint8_t)x;
	}
	return v;
}

// Reads until EOF (0), error (<0) or `limit` bytes; gives up after `timeout_s`.
struct ReadResult {
	std::vector<uint8_t> data;
	long last = 0; // last receive() return value
	bool timed_out = false;
};

ReadResult read_all(th_stack *s, int fd, size_t limit, int timeout_s)
{
	ReadResult r;
	auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(timeout_s);
	std::vector<uint8_t> buf(65536);
	while (r.data.size() < limit) {
		int left_ms = (int)std::chrono::duration_cast<std::chrono::milliseconds>(
				  deadline - std::chrono::steady_clock::now())
				  .count();
		if (left_ms <= 0) {
			r.timed_out = true;
			return r;
		}
		auto n = call_with_timeout<long>(
		    [s, fd, &buf] { return th_recv(s, fd, buf.data(), buf.size()); }, left_ms);
		if (!n) {
			r.timed_out = true;
			return r;
		}
		r.last = *n;
		if (*n <= 0)
			return r;
		r.data.insert(r.data.end(), buf.begin(), buf.begin() + *n);
	}
	return r;
}

class Transfer : public ::testing::Test
{
      protected:
	Link *link = nullptr;
	uint16_t next_port = 20000;

	void SetUp() override
	{
		const auto *info = ::testing::UnitTest::GetInstance()->current_test_info();
		uint32_t seed = (uint32_t)std::hash<std::string>{}(info->name());
		link = new Link(IP_A, IP_B, seed); // never deleted: see Link::close()
		link->start_stacks();
	}

	void TearDown() override
	{
		if (HasFailure()) {
			for (int d = 0; d < 2; d++)
				std::fprintf(
				    stderr,
				    "  link %s: sent %llu dropped %llu duplicated %llu reordered "
				    "%llu ingress-full %llu\n",
				    d == 0 ? "A->B" : "B->A",
				    (unsigned long long)link->stats[d].sent.load(),
				    (unsigned long long)link->stats[d].dropped.load(),
				    (unsigned long long)link->stats[d].duplicated.load(),
				    (unsigned long long)link->stats[d].reordered.load(),
				    (unsigned long long)link->stats[d].ingress_full.load());
		}
		link->close();
	}

	struct Pair {
		int client_fd = -1; // on B
		int server_fd = -1; // on A
		int listen_fd = -1;
		uint16_t port = 0;
	};

	// A listens, B connects
	Pair connect_pair(int timeout_ms = 10000)
	{
		Pair p;
		p.port = next_port++;
		p.listen_fd = th_listen(link->a, p.port);
		if (p.listen_fd < 0)
			throw std::runtime_error("listen failed");
		th_stack *a = link->a, *b = link->b;
		int lfd = p.listen_fd;
		uint16_t port = p.port, local = next_port++;
		Pending<int> acc([a, lfd] { return th_accept(a, lfd); });
		auto c = call_with_timeout<int>(
		    [b, local, port] { return th_connect(b, local, IP_A, port); }, timeout_ms);
		if (!c || *c < 0)
			throw std::runtime_error("connect failed or timed out");
		auto s = acc.wait(timeout_ms);
		if (!s || *s < 0)
			throw std::runtime_error("accept failed or timed out");
		p.client_fd = *c;
		p.server_fd = *s;
		return p;
	}

	// sends `data` from (s, fd) on its own thread, then ends the send side
	static Pending<long> send_then_fin(th_stack *s, int fd, std::vector<uint8_t> data)
	{
		return Pending<long>([s, fd, data] {
			long r = th_send(s, fd, data.data(), data.size());
			th_end_send(s, fd);
			return r;
		});
	}

	void one_way(size_t bytes, int timeout_s)
	{
		Pair p = connect_pair();
		auto data = pattern(bytes, 11);
		auto sender = send_then_fin(link->b, p.client_fd, data);
		ReadResult r = read_all(link->a, p.server_fd, bytes + 1, timeout_s);
		EXPECT_FALSE(r.timed_out)
		    << "transfer stalled after " << r.data.size() << " of " << bytes << " bytes";
		EXPECT_EQ(r.last, 0) << "expected EOF after the data";
		ASSERT_EQ(r.data.size(), bytes);
		EXPECT_TRUE(r.data == data) << "received data differs from what was sent";
		auto sent = sender.wait(5000);
		ASSERT_TRUE(sent.has_value()) << "sender still blocked";
		EXPECT_EQ(*sent, (long)bytes);
	}
};

} // namespace

TEST_F(Transfer, OneMegabyteOnACleanLink)
{
	one_way(1 << 20, 60);
}

TEST_F(Transfer, EightMegabytesOnACleanLink)
{
	one_way(8 << 20, 120);
}

TEST_F(Transfer, BothDirectionsAtOnce)
{
	Pair p = connect_pair();
	size_t n = 2 << 20;
	auto ab = pattern(n, 1), ba = pattern(n, 2);
	auto s1 = send_then_fin(link->a, p.server_fd, ab);
	auto s2 = send_then_fin(link->b, p.client_fd, ba);
	th_stack *a = link->a, *b = link->b;
	int cfd = p.client_fd, sfd = p.server_fd;
	Pending<ReadResult> r_on_b([b, cfd, n] { return read_all(b, cfd, n + 1, 90); });
	ReadResult r_on_a = read_all(a, sfd, n + 1, 90);
	auto rb = r_on_b.wait(95000);
	ASSERT_TRUE(rb.has_value());
	EXPECT_TRUE(r_on_a.data == ba) << "A received " << r_on_a.data.size() << " bytes";
	EXPECT_TRUE(rb->data == ab) << "B received " << rb->data.size() << " bytes";
	EXPECT_EQ(r_on_a.last, 0);
	EXPECT_EQ(rb->last, 0);
}

TEST_F(Transfer, TwoPercentLoss)
{
	Impairments im;
	im.loss = 0.02;
	link->set(im);
	one_way(1 << 20, 180);
}

TEST_F(Transfer, ReorderingAndJitter)
{
	Impairments im;
	im.delay_ms = 2;
	im.jitter_ms = 3;
	im.reorder = 0.05;
	link->set(im);
	one_way(1 << 20, 180);
}

TEST_F(Transfer, DuplicatedFrames)
{
	Impairments im;
	im.duplicate = 0.05;
	link->set(im);
	one_way(1 << 20, 120);
}

TEST_F(Transfer, EverythingAtOnce)
{
	Impairments im;
	im.loss = 0.02;
	im.duplicate = 0.02;
	im.reorder = 0.03;
	im.delay_ms = 3;
	im.jitter_ms = 4;
	link->set(im);
	one_way(512 << 10, 240);
}

TEST_F(Transfer, LossOnlyOnTheAckPath)
{
	Impairments im;
	im.loss = 0.10;
	link->set_a_to_b(im); // A receives the data and sends the ACKs
	one_way(1 << 20, 180);
}

TEST_F(Transfer, SixteenConnectionsInParallel)
{
	const int N = 16;
	const size_t n = 256 << 10;
	std::vector<Pair> pairs;
	for (int i = 0; i < N; i++)
		pairs.push_back(connect_pair());
	std::vector<Pending<long>> senders;
	for (int i = 0; i < N; i++)
		senders.push_back(send_then_fin(link->b, pairs[i].client_fd, pattern(n, 100 + i)));
	std::vector<Pending<ReadResult>> readers;
	th_stack *a = link->a;
	for (int i = 0; i < N; i++) {
		int fd = pairs[i].server_fd;
		readers.emplace_back([a, fd, n] { return read_all(a, fd, n + 1, 150); });
	}
	for (int i = 0; i < N; i++) {
		auto r = readers[i].wait(160000);
		ASSERT_TRUE(r.has_value()) << "reader " << i << " stuck";
		EXPECT_TRUE(r->data == pattern(n, 100 + i))
		    << "connection " << i << ": " << r->data.size() << " bytes";
		EXPECT_EQ(r->last, 0) << "connection " << i;
	}
}

TEST_F(Transfer, SlowReaderSeesZeroWindowAndRecovers)
{
	Pair p = connect_pair();
	size_t n = 3 << 20; // well over the 512 KB receive buffer
	auto data = pattern(n, 5);
	auto sender = send_then_fin(link->b, p.client_fd, data);
	std::vector<uint8_t> got;
	std::vector<uint8_t> buf(64 << 10);
	auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(180);
	int pauses = 0;
	while (std::chrono::steady_clock::now() < deadline) {
		th_stack *a = link->a;
		int fd = p.server_fd;
		auto r = call_with_timeout<long>(
		    [a, fd, &buf] { return th_recv(a, fd, buf.data(), buf.size()); }, 30000);
		ASSERT_TRUE(r.has_value())
		    << "receive blocked for 30 s at " << got.size() << " bytes";
		if (*r <= 0)
			break;
		got.insert(got.end(), buf.begin(), buf.begin() + *r);
		if (got.size() > (size_t)(pauses + 1) * (1u << 20) && pauses < 2) {
			pauses++;
			std::this_thread::sleep_for(
			    std::chrono::milliseconds(2500)); // let the window close
		}
	}
	EXPECT_EQ(got.size(), n);
	EXPECT_TRUE(got == data);
}

TEST_F(Transfer, HalfCloseThenReply)
{
	Pair p = connect_pair();
	auto req = pattern(10000, 8);
	auto s1 = send_then_fin(link->b, p.client_fd, req);
	ReadResult r = read_all(link->a, p.server_fd, req.size() + 1, 30);
	ASSERT_EQ(r.last, 0) << "server should see EOF after the request";
	ASSERT_TRUE(r.data == req);
	// server answers after the client's FIN (client is in FIN_WAIT_2)
	auto resp = pattern(300000, 9);
	auto s2 = send_then_fin(link->a, p.server_fd, resp);
	ReadResult r2 = read_all(link->b, p.client_fd, resp.size() + 1, 60);
	EXPECT_EQ(r2.last, 0);
	EXPECT_TRUE(r2.data == resp) << "client got " << r2.data.size() << " bytes in FIN_WAIT_2";
}

TEST_F(Transfer, ConnectionChurn)
{
	for (int i = 0; i < 40; i++) {
		Pair p = connect_pair();
		auto d = pattern(2000 + i * 100, i);
		auto s = send_then_fin(link->b, p.client_fd, d);
		ReadResult r = read_all(link->a, p.server_fd, d.size() + 1, 20);
		ASSERT_TRUE(r.data == d) << "round " << i;
		ASSERT_EQ(r.last, 0) << "round " << i;
		th_end_send(link->a, p.server_fd);
		th_close(link->a, p.server_fd);
		th_close(link->b, p.client_fd);
		th_close(link->a, p.listen_fd);
	}
}

TEST_F(Transfer, LoopbackOnOneStack)
{
	// client and server on the same stack: frames go through its own ingress queue
	th_stack *a = link->a;
	int l = th_listen(a, 7000);
	ASSERT_GE(l, 0);
	Pending<int> acc([a, l] { return th_accept(a, l); });
	auto c = call_with_timeout<int>([a] { return th_connect(a, 7001, IP_A, 7000); }, 10000);
	ASSERT_TRUE(c.has_value());
	ASSERT_GE(*c, 0);
	auto s = acc.wait(10000);
	ASSERT_TRUE(s.has_value());
	auto data = pattern(1 << 20, 3);
	auto sender = send_then_fin(a, *c, data);
	ReadResult r = read_all(a, *s, data.size() + 1, 60);
	EXPECT_EQ(r.last, 0);
	EXPECT_TRUE(r.data == data) << r.data.size() << " bytes over loopback";
}

// Echo: A sends back everything it reads while B keeps sending, so both receive buffers
// fill and both sides depend on ACKs that arrive while their own receive window is zero.
// The same pattern stalls against Linux (see ZeroReceiveWindow in the unit tests): two
// copies of this stack don't trigger it, because neither probes a closed window with data.
TEST_F(Transfer, EchoServerUnderFullBuffers)
{
	Pair p = connect_pair();
	const size_t n = 20 << 20;
	auto data = pattern(n, 21);
	th_stack *a = link->a, *b = link->b;
	int sfd = p.server_fd, cfd = p.client_fd;
	Pending<long> echo([a, sfd] {
		std::vector<uint8_t> buf(64 << 10);
		long total = 0, r;
		while ((r = th_recv(a, sfd, buf.data(), buf.size())) > 0) {
			if (th_send(a, sfd, buf.data(), (size_t)r) != r)
				return -1L;
			total += r;
		}
		th_end_send(a, sfd);
		return r < 0 ? r : total;
	});
	auto sender = send_then_fin(b, cfd, data);
	ReadResult r = read_all(b, cfd, n + 1, 120);
	EXPECT_FALSE(r.timed_out) << "echo stalled after " << r.data.size() << " of " << n
				  << " bytes";
	EXPECT_EQ(r.data.size(), n);
	EXPECT_TRUE(r.data == data);
}
