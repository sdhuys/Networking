// Below TCP: ARP resolution with retries (finding 16 follow-ups), routing through a gateway,
// IPv4 header handling (options, total length, finding 30) and UDP checksums (finding 31).

#include "frames.hpp"
#include "stack_fixture.hpp"

#include <numeric>

// ------------------------------------------------------------------ ARP

// A second stack whose frames are captured raw, with its own clock-driven loop.
class Neighbour : public StackTest
{
      protected:
	std::vector<std::vector<uint8_t>> raw;
	std::mutex raw_mu;
	th_stack *s = nullptr;

	static void capture(void *user, const uint8_t *f, size_t n)
	{
		auto *self = static_cast<Neighbour *>(user);
		std::lock_guard<std::mutex> g(self->raw_mu);
		self->raw.emplace_back(f, f + n);
	}

	size_t arp_requests_for(const Ip &target)
	{
		std::lock_guard<std::mutex> g(raw_mu);
		size_t n = 0;
		for (auto &f : raw)
			if (is_arp_request_for(f, target))
				n++;
		return n;
	}

	std::vector<std::vector<uint8_t>> take_raw()
	{
		std::lock_guard<std::mutex> g(raw_mu);
		auto v = std::move(raw);
		raw.clear();
		return v;
	}

	// moves the fake clock in `step` ms steps, running this stack's timers and TX worker
	void run(uint64_t ms, uint64_t step = 50)
	{
		for (uint64_t done = 0; done < ms; done += step) {
			fake_clock_advance(step);
			guarded("running the neighbour stack", [this] {
				th_run_timers(s);
				th_pump_tx(s);
				return 0;
			});
		}
	}

	// pumps the TX worker until the stack has sent something (another thread is in connect)
	void wait_for_frame()
	{
		for (int i = 0; i < 2000; i++) {
			guarded("TX", [this] { return th_pump_tx(s); });
			{
				std::lock_guard<std::mutex> g(raw_mu);
				if (!raw.empty())
					return;
			}
			std::this_thread::sleep_for(std::chrono::milliseconds(1));
		}
		throw std::runtime_error("the stack sent nothing");
	}

	void inject_into(const std::vector<uint8_t> &f)
	{
		guarded("injecting into the neighbour stack",
			[this, f] { return th_inject(s, f.data(), f.size()); });
	}

	// a RST+ACK from `from` to the SYN in `syn_frame`, so a connect() thread ends
	void refuse(const std::vector<uint8_t> &syn_frame, const Mac &via)
	{
		auto syn = parse(syn_frame);
		ASSERT_TRUE(syn.has_value());
		TcpSegment rst;
		rst.src_mac = via;
		rst.dst_mac = stack_mac;
		rst.src_ip = syn->dst_ip;
		rst.dst_ip = syn->src_ip;
		rst.src_port = syn->dst_port;
		rst.dst_port = syn->src_port;
		rst.ack = syn->seq + 1;
		rst.flags = RST | ACK;
		inject_into(build(rst));
	}
};

TEST_F(Neighbour, UnansweredRequestIsRetriedThenTheEntryIsDropped)
{
	s = th_stack_create("10.0.9.2", stack_mac.data(), &Neighbour::capture, this);
	const Ip target = ip("10.0.9.1");
	Pending<int> conn([this] { return th_connect(s, 50100, "10.0.9.1", 80); });
	wait_for_frame();
	ASSERT_EQ(arp_requests_for(target), 1u) << "the SYN waits for ARP";

	run(3900);
	EXPECT_EQ(arp_requests_for(target), 4u)
	    << "first request plus ARP_MAX_RETRIES (3) retries, one per ARP_RETRY_MS (1 s)";

	// at +4 s the entry is given up. The SYN retransmissions at +1 s and +3 s were queued
	// on it; the next one (+7 s) starts a fresh resolution.
	run(3000);
	EXPECT_EQ(arp_requests_for(target), 4u) << "no requests between giving up and the next SYN";
	run(1000);
	EXPECT_EQ(arp_requests_for(target), 5u) << "a new packet starts a new resolution";

	// let connect give up; every packet queued on an abandoned entry must be back in the
	// pool (checked by the fixture after the test)
	for (int i = 0; i < 400 && !conn.wait(0).has_value(); i++)
		run(1000, 100);
	auto r = conn.wait(2000);
	ASSERT_TRUE(r.has_value()) << "connect never gave up";
	EXPECT_LT(*r, 0);
	run(5000, 100); // the last entry's retries run out
}

TEST_F(Neighbour, ReplyFlushesEveryQueuedPacketInOrder)
{
	s = th_stack_create("10.0.9.2", stack_mac.data(), &Neighbour::capture, this);
	int u = th_udp_open(s, 7000);
	ASSERT_GE(u, 0);
	for (uint8_t i = 0; i < 5; i++) {
		std::vector<uint8_t> d(10, i);
		ASSERT_EQ(th_udp_sendto(s, u, d.data(), d.size(), "10.0.9.1", 7001), 10);
	}
	guarded("TX", [this] { return th_pump_tx(s); });
	auto first = take_raw();
	ASSERT_EQ(first.size(), 1u) << "one ARP request for five queued datagrams";
	EXPECT_TRUE(is_arp_request_for(first[0], ip("10.0.9.1")));

	Mac nb{0x02, 0, 0, 0, 0, 0x66};
	inject_into(build_arp_reply(nb, ip("10.0.9.1"), stack_mac, ip("10.0.9.2")));
	auto out = take_raw();
	ASSERT_EQ(out.size(), 5u) << "all queued datagrams go out on the reply";
	for (uint8_t i = 0; i < 5; i++) {
		ASSERT_TRUE(is_udp(out[i]));
		EXPECT_TRUE(std::equal(nb.begin(), nb.end(), out[i].begin()))
		    << "to the resolved MAC";
		EXPECT_EQ(out[i][42], i) << "in the order they were sent";
	}
	th_close(s, u);
}

TEST_F(Neighbour, UnsolicitedReplyCreatesNoEntry)
{
	s = th_stack_create("10.0.9.2", stack_mac.data(), &Neighbour::capture, this);
	Mac nb{0x02, 0, 0, 0, 0, 0x67};
	inject_into(build_arp_reply(nb, ip("10.0.9.50"), stack_mac, ip("10.0.9.2")));
	int u = th_udp_open(s, 7002);
	std::vector<uint8_t> d(4, 1);
	th_udp_sendto(s, u, d.data(), d.size(), "10.0.9.50", 7003);
	guarded("TX", [this] { return th_pump_tx(s); });
	auto out = take_raw();
	ASSERT_EQ(out.size(), 1u);
	EXPECT_TRUE(is_arp_request_for(out[0], ip("10.0.9.50")))
	    << "an unrequested reply must not be cached";
	inject_into(build_arp_reply(nb, ip("10.0.9.50"), stack_mac, ip("10.0.9.2")));
	take_raw();
	th_close(s, u);
}

// ------------------------------------------------------------------ routing

TEST_F(Neighbour, OffSubnetTrafficGoesToTheGateway)
{
	s = th_stack_create_gw(
	    "10.0.10.2", stack_mac.data(), "10.0.10.254", &Neighbour::capture, this);
	Pending<int> conn([this] { return th_connect(s, 50200, "8.8.8.8", 80); });
	wait_for_frame();
	auto first = take_raw();
	ASSERT_EQ(first.size(), 1u);
	EXPECT_TRUE(is_arp_request_for(first[0], ip("10.0.10.254")))
	    << "ARP is for the next hop, not the destination";

	Mac gw{0x02, 0, 0, 0, 0, 0xFE};
	inject_into(build_arp_reply(gw, ip("10.0.10.254"), stack_mac, ip("10.0.10.2")));
	auto out = take_raw();
	ASSERT_EQ(out.size(), 1u);
	auto syn = parse(out[0]);
	ASSERT_TRUE(syn.has_value());
	EXPECT_EQ(syn->flags, SYN);
	EXPECT_EQ(syn->dst_mac, gw) << "sent to the gateway's MAC";
	EXPECT_EQ(syn->dst_ip, ip("8.8.8.8")) << "addressed to the real destination";
	EXPECT_EQ(syn->src_ip, ip("10.0.10.2")) << "from our address on that interface";
	refuse(out[0], gw);
	conn.wait(2000);
}

TEST_F(Neighbour, NoRouteMeansConnectFailsAndNothingIsSent)
{
	s = th_stack_create("10.0.11.2", stack_mac.data(), &Neighbour::capture, this);
	auto r = call_with_timeout<int>([this] { return th_connect(s, 50300, "8.8.8.8", 80); },
					2000);
	ASSERT_TRUE(r.has_value()) << "connect without a route must fail at once, not block";
	EXPECT_LT(*r, 0);
	guarded("TX", [this] { return th_pump_tx(s); });
	EXPECT_TRUE(take_raw().empty());
}

// ------------------------------------------------------------------ IPv4

class Ipv4 : public StackTest
{
      protected:
	int l = -1;
	PeerConn c;
	void SetUp() override
	{
		StackTest::SetUp();
		l = listen(9000);
		c = open_passive(l, 9000, 46000);
	}
	int inject_frame(const std::vector<uint8_t> &f)
	{
		return guarded("injecting a frame",
			       [this, f] { return th_inject(st, f.data(), f.size()); });
	}
	std::vector<uint8_t> data_frame(const std::vector<uint8_t> &payload)
	{
		TcpSegment s = seg_for(c, ACK | PSH);
		s.payload = payload;
		return build(s);
	}
};

TEST_F(Ipv4, HeaderWithOptionsIsAccepted)
{
	auto f = data_frame(pattern(20, 5));
	// insert 4 bytes of options (NOP NOP NOP EOL) after the 20-byte IP header
	f.insert(f.begin() + 34, {0x01, 0x01, 0x01, 0x00});
	f[14] = 0x46; // IHL 6
	uint16_t tot = (uint16_t)(be16(f, 16) + 4);
	f[16] = (uint8_t)(tot >> 8);
	f[17] = (uint8_t)tot;
	fix_ip_checksum(f);
	inject_frame(f);
	c.peer_nxt += 20;
	EXPECT_EQ(info(c).rcv_nxt, c.peer_nxt) << "IP options must be skipped, not rejected";
	EXPECT_EQ(app_read(c, 20), pattern(20, 5));
	drain_out();
}

// Finding 30: Ethernet pads short frames to 60 bytes; the IPv4 total length says where
// the packet ends.
TEST_F(Ipv4, PaddedFrameIsAccepted)
{
	TcpSegment s = seg_for(c, ACK | PSH);
	s.payload = {0x42};
	s.opts.ts.reset(); // keep the frame under the 60-byte minimum
	auto f = build(s);
	ASSERT_LT(f.size(), 60u);
	f.resize(60, 0xAA); // what a real NIC delivers (padding needn't be zero)
	inject_frame(f);
	c.peer_nxt += 1;
	EXPECT_EQ(info(c).rcv_nxt, c.peer_nxt) << "the 1-byte segment was rejected";
	EXPECT_EQ(app_read(c, 1), std::vector<uint8_t>{0x42}) << "padding leaked into the data";
	drain_out();
}

TEST_F(Ipv4, TotalLengthBeyondTheFrameIsDropped)
{
	auto f = data_frame(pattern(20, 6));
	uint16_t tot = (uint16_t)(be16(f, 16) + 100);
	f[16] = (uint8_t)(tot >> 8);
	f[17] = (uint8_t)tot;
	fix_ip_checksum(f);
	inject_frame(f);
	EXPECT_EQ(info(c).rcv_nxt, c.peer_nxt) << "a packet claiming more bytes than arrived";
	expect_nothing_out("a malformed packet is dropped silently");
}

TEST_F(Ipv4, HeaderLengthBelowTwentyBytesIsDropped)
{
	auto f = data_frame(pattern(20, 7));
	f[14] = 0x44; // IHL 4 = 16 bytes
	fix_ip_checksum(f);
	inject_frame(f);
	EXPECT_EQ(info(c).rcv_nxt, c.peer_nxt);
	expect_nothing_out("a malformed packet is dropped silently");
}

// ------------------------------------------------------------------ UDP (finding 31)

class Udp : public StackTest
{
      protected:
	int u = -1;
	static constexpr uint16_t PORT = 5353;
	void SetUp() override
	{
		StackTest::SetUp();
		u = th_udp_open(st, PORT);
		ASSERT_GE(u, 0);
	}
	void TearDown() override
	{
		th_close(st, u);
		StackTest::TearDown();
	}
	std::vector<uint8_t> send_and_capture(const std::vector<uint8_t> &d, uint16_t dport = 6000)
	{
		long r = th_udp_sendto(st, u, d.data(), d.size(), PEER_IP, dport);
		if (r != (long)d.size())
			throw std::runtime_error("sendto failed: " + std::to_string(r));
		auto frames = take_raw_frames();
		for (auto &f : frames)
			if (is_udp(f))
				return f;
		throw std::runtime_error("no UDP datagram sent");
	}
};

TEST_F(Udp, OutgoingChecksumIsValid)
{
	auto f = send_and_capture(pattern(37, 1)); // odd length: tests the padding byte too
	uint16_t sport = be16(f, 34), dport = be16(f, 36), len = be16(f, 38), csum = be16(f, 40);
	EXPECT_EQ(sport, PORT);
	EXPECT_EQ(dport, 6000);
	EXPECT_EQ(len, 8 + 37);
	EXPECT_NE(csum, 0) << "the stack computes checksums, so 0 (= none) must never be sent";
	EXPECT_EQ(udp_sum(f), 0xFFFFu) << "checksum doesn't verify (byte order?)";
	EXPECT_TRUE(std::equal(f.begin() + 42, f.end(), pattern(37, 1).begin()));
}

TEST_F(Udp, ComputedZeroChecksumIsSentAsAllOnes)
{
	// choose two payload bytes so the checksum the stack computes is exactly 0:
	// the sum of everything else, plus those bytes, must be 0xFFFF
	std::vector<uint8_t> d = {0, 0};
	auto probe = build_udp(stack_mac, peer_mac, ip(STACK_IP), ip(PEER_IP), PORT, 6001, d);
	probe[40] = probe[41] = 0;
	uint32_t rest = udp_sum(probe); // with payload 0x0000 and checksum 0
	uint16_t x = (uint16_t)(0xFFFF - rest);
	d = {(uint8_t)(x >> 8), (uint8_t)x};

	auto f = send_and_capture(d, 6001);
	EXPECT_EQ(be16(f, 40), 0xFFFF) << "RFC 768: a computed checksum of 0 is sent as 0xFFFF";
	EXPECT_EQ(udp_sum(f), 0xFFFFu);
}

TEST_F(Udp, IncomingDatagramIsDeliveredWithItsSource)
{
	auto f = build_udp(
	    peer_mac, stack_mac, ip(PEER_IP), ip(STACK_IP), 6002, PORT, pattern(100, 2));
	guarded("UDP in", [this, f] { return th_inject(st, f.data(), f.size()); });
	struct Out {
		std::vector<uint8_t> buf = std::vector<uint8_t>(200);
		uint8_t src[4] = {};
		uint16_t sport = 0;
	};
	auto o = std::make_shared<Out>();
	int fd = u;
	auto r = call_with_timeout<long>(
	    [this, fd, o] {
		    return th_udp_recvfrom(st, fd, o->buf.data(), o->buf.size(), o->src, &o->sport);
	    },
	    2000);
	ASSERT_TRUE(r.has_value()) << "receive_from blocked";
	ASSERT_EQ(*r, 100);
	o->buf.resize(100);
	EXPECT_EQ(o->buf, pattern(100, 2));
	EXPECT_EQ(Ip({o->src[0], o->src[1], o->src[2], o->src[3]}), ip(PEER_IP));
	EXPECT_EQ(o->sport, 6002);
}

TEST_F(Udp, IncomingDatagramWithBadChecksumIsDropped)
{
	auto bad = build_udp(
	    peer_mac, stack_mac, ip(PEER_IP), ip(STACK_IP), 6003, PORT, pattern(10, 3));
	bad[42] ^= 0xFF; // corrupt the data, keep the checksum
	guarded("UDP in", [this, bad] { return th_inject(st, bad.data(), bad.size()); });
	auto good = build_udp(peer_mac, stack_mac, ip(PEER_IP), ip(STACK_IP), 6003, PORT, {7, 7});
	guarded("UDP in", [this, good] { return th_inject(st, good.data(), good.size()); });

	auto buf = std::make_shared<std::vector<uint8_t>>(64);
	int fd = u;
	auto r = call_with_timeout<long>(
	    [this, fd, buf] {
		    uint8_t src[4];
		    uint16_t sport;
		    return th_udp_recvfrom(st, fd, buf->data(), buf->size(), src, &sport);
	    },
	    2000);
	ASSERT_TRUE(r.has_value());
	EXPECT_EQ(*r, 2)
	    << "the first datagram read must be the good one: the corrupt one is dropped";
}
