// Malformed and hostile input: bad checksums, truncated headers, bogus flags, frames for
// other hosts, ARP, and a fuzz run of randomly mutated segments. Build with
// -DSTACK_SANITIZE=address to turn silent memory errors into failures.

#include "stack_fixture.hpp"

#include <random>

class Robustness : public StackTest
{
      protected:
	int l = -1;
	PeerConn c;
	void SetUp() override
	{
		StackTest::SetUp();
		l = listen(9000);
		c = open_passive(l, 9000, 43000);
	}
	int inject_raw(const std::vector<uint8_t> &f)
	{
		return guarded("processing a raw frame",
			       [this, f] { return th_inject(st, f.data(), f.size()); });
	}
};

TEST_F(Robustness, BadIpChecksumIsDropped)
{
	TcpSegment s = seg_for(c, ACK | PSH);
	s.payload = pattern(100);
	auto f = build(s);
	f[14 + 10] ^= 0x55;
	inject_raw(f);
	advance(500);
	expect_nothing_out("bad IP checksum");
	EXPECT_EQ(info(c).rcv_nxt, c.peer_nxt);
}

TEST_F(Robustness, TruncatedFramesAreDropped)
{
	TcpSegment s = seg_for(c, ACK | PSH);
	s.payload = pattern(100);
	auto f = build(s);
	for (size_t cut : {0u, 10u, 14u, 20u, 33u, 34u, 40u, 53u}) {
		std::vector<uint8_t> t(f.begin(), f.begin() + cut);
		inject_raw(t);
	}
	expect_nothing_out("truncated frames");
	EXPECT_EQ(info(c).state, TH_ESTABLISHED);
}

TEST_F(Robustness, DataOffsetBeyondTheSegmentIsDropped)
{
	TcpSegment s = seg_for(c, ACK);
	auto f = build(s);
	f[14 + 20 + 12] = 0xF0; // 60-byte header in a 20-byte segment
	inject_raw(f);
	expect_nothing_out("header length larger than the segment");
}

TEST_F(Robustness, SynFinIsDropped)
{
	PeerConn n;
	n.stack_port = 9000;
	n.peer_port = 43001;
	n.peer_nxt = 5;
	inject(seg_for(n, SYN | FIN));
	expect_nothing_out("SYN+FIN is never valid");
	EXPECT_FALSE(exists(n));
}

TEST_F(Robustness, FrameForAnotherMacIsIgnored)
{
	TcpSegment s = seg_for(c, ACK | PSH);
	s.payload = pattern(10);
	s.dst_mac = {0x02, 9, 9, 9, 9, 9};
	inject(s);
	advance(500);
	expect_nothing_out("frame for another host");
	EXPECT_EQ(info(c).rcv_nxt, c.peer_nxt);
}

TEST_F(Robustness, PacketForAnotherIpIsIgnored)
{
	TcpSegment s = seg_for(c, ACK | PSH);
	s.payload = pattern(10);
	s.dst_ip = ip("10.0.0.99");
	inject(s);
	advance(500);
	expect_nothing_out("packet for another IP");
}

TEST_F(Robustness, FuzzedSegmentsNeverCrashOrLeak)
{
	std::mt19937 rng(42);
	TcpSegment base = seg_for(c, ACK | PSH);
	base.payload = pattern(300);
	auto good = build(base);
	for (int i = 0; i < 3000; i++) {
		auto f = good;
		int flips = 1 + rng() % 6;
		for (int k = 0; k < flips; k++) {
			// mostly the IP and TCP headers, sometimes anywhere
			size_t at = (rng() % 4 == 0) ? rng() % f.size() : 14 + rng() % 60;
			if (at < f.size())
				f[at] = (uint8_t)rng();
		}
		if (rng() % 10 == 0)
			f.resize(rng() % f.size());
		inject_raw(f);
		drain_out();
	}
	advance(2000);
	drain_out();
	// the connection may have been reset by a lucky mutation; the stack must still answer
	PeerConn n;
	n.stack_port = 9000;
	n.peer_port = 43999;
	n.peer_nxt = 1;
	inject(seg_for(n, SYN));
	TcpSegment sa = next_out("SYN-ACK after the fuzz run");
	EXPECT_EQ(sa.flags, SYN | ACK);
}

// ------------------------------------------------------------------ ARP

class Arp : public StackTest
{
      protected:
	std::vector<std::vector<uint8_t>> raw;
	static void capture(void *user, const uint8_t *f, size_t n)
	{
		static_cast<Arp *>(user)->raw.emplace_back(f, f + n);
	}
};

TEST_F(Arp, RequestForOurAddressGetsAReply)
{
	th_stack *s = th_stack_create("10.0.5.2", stack_mac.data(), &Arp::capture, this);
	Mac asker{0x02, 0, 0, 0, 0, 0x77};
	auto req = build_arp_request(asker, ip("10.0.5.1"), ip("10.0.5.2"));
	guarded("ARP request", [s, req] { return th_inject(s, req.data(), req.size()); });
	ASSERT_EQ(raw.size(), 1u) << "one ARP reply expected";
	auto &r = raw[0];
	ASSERT_GE(r.size(), 42u);
	EXPECT_EQ(ethertype(r), 0x0806);
	EXPECT_TRUE(std::equal(asker.begin(), asker.end(), r.begin()))
	    << "unicast back to the asker";
	EXPECT_EQ((r[20] << 8) | r[21], 2) << "operation = reply";
	EXPECT_TRUE(std::equal(stack_mac.begin(), stack_mac.end(), r.begin() + 22))
	    << "sender MAC = ours";
	EXPECT_EQ(r[28], 10);
	EXPECT_EQ(r[31], 2) << "sender IP = ours";
}

TEST_F(Arp, RequestForAnotherAddressIsIgnored)
{
	th_stack *s = th_stack_create("10.0.6.2", stack_mac.data(), &Arp::capture, this);
	auto req = build_arp_request(peer_mac, ip("10.0.6.1"), ip("10.0.6.50"));
	guarded("ARP request", [s, req] { return th_inject(s, req.data(), req.size()); });
	EXPECT_TRUE(raw.empty());
}

TEST_F(Arp, UnresolvedNeighbourIsResolvedThenQueuedDataSent)
{
	th_stack *s = th_stack_create("10.0.7.2", stack_mac.data(), &Arp::capture, this);
	Pending<int> conn([s] { return th_connect(s, 50000, "10.0.7.1", 80); });
	for (int i = 0; i < 2000 && raw.empty(); i++) {
		guarded("TX", [s] { return th_pump_tx(s); });
		std::this_thread::sleep_for(std::chrono::milliseconds(1));
	}
	ASSERT_FALSE(raw.empty());
	EXPECT_TRUE(is_arp_request_for(raw[0], ip("10.0.7.1")))
	    << "first frame must be an ARP request";
	Mac nb{0x02, 0, 0, 0, 0, 0x55};
	auto rep = build_arp_reply(nb, ip("10.0.7.1"), stack_mac, ip("10.0.7.2"));
	raw.clear();
	guarded("ARP reply", [s, rep] { return th_inject(s, rep.data(), rep.size()); });
	ASSERT_EQ(raw.size(), 1u) << "the queued SYN goes out once the neighbour is known";
	auto syn = parse(raw[0]);
	ASSERT_TRUE(syn.has_value());
	EXPECT_EQ(syn->flags, SYN);
	EXPECT_EQ(syn->dst_mac, nb);
	// refuse, so the connect thread ends
	TcpSegment rst;
	rst.src_mac = nb;
	rst.dst_mac = stack_mac;
	rst.src_ip = ip("10.0.7.1");
	rst.dst_ip = ip("10.0.7.2");
	rst.src_port = 80;
	rst.dst_port = 50000;
	rst.ack = syn->seq + 1;
	rst.flags = RST | ACK;
	auto f = build(rst);
	guarded("RST", [s, f] { return th_inject(s, f.data(), f.size()); });
	conn.wait(2000);
}
