// The non-TCP protocols through a whole stack: ICMP echo, Ethernet demultiplexing, IPv4
// input checks, strong-host address checks, loopback, UDP sockets and more ARP behaviour.

#include "frames.hpp"
#include "stack_fixture.hpp"

class L3 : public StackTest
{
      protected:
	int inject_frame(const std::vector<uint8_t> &f)
	{
		return guarded("injecting a frame",
			       [this, f] { return th_inject(st, f.data(), f.size()); });
	}
	std::vector<std::vector<uint8_t>> icmp_out()
	{
		std::vector<std::vector<uint8_t>> v;
		for (auto &f : take_raw_frames())
			if (is_icmp(f))
				v.push_back(f);
		return v;
	}
	std::vector<uint8_t> echo_request(const std::vector<uint8_t> &data,
					  const char *dst = STACK_IP,
					  bool bad = false)
	{
		return build_icmp_echo(
		    peer_mac, stack_mac, ip(PEER_IP), ip(dst), 8, 0x1234, 7, data, bad);
	}
	// a datagram from the peer to the stack (or to `dst`)
	std::vector<uint8_t> udp_in(uint16_t dport,
				    const std::vector<uint8_t> &d,
				    const char *dst = STACK_IP)
	{
		return build_udp(peer_mac, stack_mac, ip(PEER_IP), ip(dst), 6100, dport, d);
	}
	// reads one datagram with a timeout; nullopt if nothing arrives
	std::optional<std::vector<uint8_t>> udp_read(int fd, int ms = 300)
	{
		auto buf = std::make_shared<std::vector<uint8_t>>(2048);
		auto r = call_with_timeout<long>(
		    [this, fd, buf] {
			    uint8_t src[4];
			    uint16_t port;
			    return th_udp_recvfrom(st, fd, buf->data(), buf->size(), src, &port);
		    },
		    ms);
		if (!r || *r < 0)
			return std::nullopt;
		buf->resize((size_t)*r);
		return *buf;
	}
	// after a udp_read that timed out, its reader is still blocked: give it a datagram so
	// that thread ends before the socket is closed
	void unblock(int fd, uint16_t port)
	{
		(void)fd;
		inject_frame(udp_in(port, {0xEE}));
		std::this_thread::sleep_for(std::chrono::milliseconds(20));
	}
};

// ------------------------------------------------------------------ ICMP

TEST_F(L3, EchoRequestGetsAMatchingReply)
{
	auto data = pattern(56, 1);
	inject_frame(echo_request(data));
	auto out = icmp_out();
	ASSERT_EQ(out.size(), 1u) << "one echo reply";
	auto &f = out[0];
	EXPECT_TRUE(std::equal(peer_mac.begin(), peer_mac.end(), f.begin()))
	    << "to the asker's MAC";
	EXPECT_EQ(Ip({f[26], f[27], f[28], f[29]}), ip(STACK_IP)) << "source = the address pinged";
	EXPECT_EQ(Ip({f[30], f[31], f[32], f[33]}), ip(PEER_IP));
	EXPECT_EQ(sum16(&f[14], 20), 0xFFFFu) << "IPv4 header checksum";
	EXPECT_EQ(f[34], 0) << "type 0 = echo reply";
	EXPECT_EQ(f[35], 0);
	EXPECT_EQ(be16(f, 38), 0x1234) << "identifier echoed";
	EXPECT_EQ(be16(f, 40), 7) << "sequence number echoed";
	EXPECT_EQ(sum16(&f[34], f.size() - 34), 0xFFFFu) << "ICMP checksum";
	EXPECT_TRUE(std::equal(data.begin(), data.end(), f.begin() + 42)) << "payload echoed";
}

TEST_F(L3, EchoRequestWithOddLengthPayloadIsAnswered)
{
	inject_frame(echo_request(pattern(33, 2)));
	auto out = icmp_out();
	ASSERT_EQ(out.size(), 1u);
	EXPECT_EQ(sum16(&out[0][34], out[0].size() - 34), 0xFFFFu);
}

TEST_F(L3, EchoRequestWithBadChecksumIsIgnored)
{
	inject_frame(echo_request(pattern(20), STACK_IP, true));
	EXPECT_TRUE(icmp_out().empty());
}

TEST_F(L3, EchoReplyAndUnknownTypesGetNoAnswer)
{
	inject_frame(build_icmp_echo(peer_mac, stack_mac, ip(PEER_IP), ip(STACK_IP), 0, 1, 1, {}));
	inject_frame(build_icmp_echo(peer_mac, stack_mac, ip(PEER_IP), ip(STACK_IP), 13, 1, 1, {}));
	EXPECT_TRUE(icmp_out().empty());
}

TEST_F(L3, TruncatedIcmpIsDropped)
{
	auto f = echo_request({});
	f.resize(14 + 20 + 4); // half an ICMP header
	f[17] = 24;	       // IP total length to match
	fix_ip_checksum(f);
	inject_frame(f);
	EXPECT_TRUE(icmp_out().empty());
}

// strong host: a frame arriving on test0 is only for test0's address
TEST_F(L3, LoopbackAddressArrivingOnTheWireIsIgnored)
{
	inject_frame(echo_request(pattern(8), "127.0.0.1"));
	EXPECT_TRUE(icmp_out().empty()) << "127/8 must never be accepted from outside";
}

// ------------------------------------------------------------------ Ethernet

TEST_F(L3, UnsupportedEthertypesAreDropped)
{
	auto f = echo_request(pattern(8));
	for (uint16_t et : {0x86DD, 0x8100, 0x88CC}) { // IPv6, VLAN, LLDP
		auto g = f;
		g[12] = (uint8_t)(et >> 8);
		g[13] = (uint8_t)et;
		inject_frame(g);
	}
	EXPECT_TRUE(take_raw_frames().empty());
}

TEST_F(L3, ZeroDestinationMacIsOnlyForLoopback)
{
	auto f = echo_request(pattern(8));
	std::fill(f.begin(), f.begin() + 6, 0);
	inject_frame(f);
	EXPECT_TRUE(icmp_out().empty()) << "a zero MAC from the wire is not ours";
}

TEST_F(L3, BroadcastFrameAndAddressAreAccepted)
{
	int u = th_udp_open(st, 6700);
	auto f = build_udp(peer_mac,
			   Mac{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
			   ip(PEER_IP),
			   ip("255.255.255.255"),
			   6100,
			   6700,
			   {1, 2, 3});
	inject_frame(f);
	auto got = udp_read(u, 2000);
	ASSERT_TRUE(got.has_value()) << "limited broadcast to a bound port must be delivered";
	EXPECT_EQ(*got, (std::vector<uint8_t>{1, 2, 3}));
	th_close(st, u);
}

// ------------------------------------------------------------------ IPv4 input

TEST_F(L3, FragmentsAreDropped)
{
	int u = th_udp_open(st, 6701);
	auto mf = udp_in(6701, pattern(16));
	mf[20] = 0x20; // More Fragments
	fix_ip_checksum(mf);
	inject_frame(mf);
	auto off = udp_in(6701, pattern(16));
	off[20] = 0x00;
	off[21] = 0x10; // fragment offset 16 * 8
	fix_ip_checksum(off);
	inject_frame(off);
	EXPECT_FALSE(udp_read(u).has_value()) << "fragments are not reassembled, so not delivered";
	unblock(u, 6701);
	th_close(st, u);
}

TEST_F(L3, WrongIpVersionIsDropped)
{
	auto f = echo_request(pattern(8));
	f[14] = 0x65; // version 6 in an IPv4 ethertype
	fix_ip_checksum(f);
	inject_frame(f);
	EXPECT_TRUE(icmp_out().empty());
}

TEST_F(L3, UnknownProtocolIsDroppedQuietly)
{
	auto f = echo_request(pattern(8));
	f[23] = 47; // GRE
	fix_ip_checksum(f);
	inject_frame(f);
	EXPECT_TRUE(take_raw_frames().empty());
}

// ------------------------------------------------------------------ UDP sockets

TEST_F(L3, DatagramsAreDemultiplexedByPort)
{
	int a = th_udp_open(st, 6800);
	int b = th_udp_open(st, 6801);
	inject_frame(udp_in(6801, {0xB}));
	inject_frame(udp_in(6800, {0xA}));
	EXPECT_EQ(udp_read(a, 2000), std::vector<uint8_t>{0xA});
	EXPECT_EQ(udp_read(b, 2000), std::vector<uint8_t>{0xB});
	th_close(st, a);
	th_close(st, b);
}

TEST_F(L3, DatagramToAnUnboundPortGetsNoReply)
{
	inject_frame(udp_in(6999, {1}));
	EXPECT_TRUE(take_raw_frames().empty());
}

TEST_F(L3, ZeroChecksumMeansNoChecksum)
{
	int u = th_udp_open(st, 6802);
	auto f = udp_in(6802, pattern(10, 4));
	f[40] = f[41] = 0; // RFC 768: the sender computed none
	inject_frame(f);
	EXPECT_EQ(udp_read(u, 2000), pattern(10, 4));
	th_close(st, u);
}

TEST_F(L3, UdpLengthThatDisagreesWithIpIsDropped)
{
	int u = th_udp_open(st, 6803);
	auto f = udp_in(6803, pattern(10, 5));
	f[39] += 4; // UDP length 4 bytes longer than the datagram
	inject_frame(f);
	EXPECT_FALSE(udp_read(u).has_value());
	unblock(u, 6803);
	th_close(st, u);
}

TEST_F(L3, PortCanBeBoundAgainAfterClose)
{
	int u = th_udp_open(st, 6804);
	ASSERT_GE(u, 0);
	EXPECT_LT(th_udp_open(st, 6804), 0) << "a port can't be bound twice";
	th_close(st, u);
	int again = th_udp_open(st, 6804);
	EXPECT_GE(again, 0) << "closing must free the port";
	inject_frame(udp_in(6804, {9}));
	EXPECT_EQ(udp_read(again, 2000), std::vector<uint8_t>{9});
	th_close(st, again);
}

// ------------------------------------------------------------------ loopback

TEST_F(L3, UdpToLoopbackStaysOffTheWire)
{
	int u = th_udp_open(st, 6900);
	std::vector<uint8_t> d = pattern(100, 6);
	ASSERT_EQ(th_udp_sendto(st, u, d.data(), d.size(), "127.0.0.1", 6900), 100);
	EXPECT_TRUE(take_raw_frames().empty()) << "loopback traffic must not reach test0";
	EXPECT_EQ(th_drain_ingress(st), 1u) << "it comes back in through the ingress queue";
	auto buf = std::make_shared<std::vector<uint8_t>>(256);
	auto src = std::make_shared<std::array<uint8_t, 4>>();
	auto port = std::make_shared<uint16_t>(0);
	auto r = call_with_timeout<long>(
	    [this, u, buf, src, port] {
		    return th_udp_recvfrom(
			st, u, buf->data(), buf->size(), src->data(), port.get());
	    },
	    2000);
	ASSERT_TRUE(r.has_value());
	ASSERT_EQ(*r, 100);
	buf->resize(100);
	EXPECT_EQ(*buf, d);
	EXPECT_EQ(Ip(*src), ip("127.0.0.1"));
	EXPECT_EQ(*port, 6900);
	th_close(st, u);
}

TEST_F(L3, UdpToOurOwnAddressGoesThroughLoopback)
{
	int u = th_udp_open(st, 6901);
	std::vector<uint8_t> d = {4, 5, 6};
	ASSERT_EQ(th_udp_sendto(st, u, d.data(), d.size(), STACK_IP, 6901), 3);
	EXPECT_TRUE(take_raw_frames().empty()) << "our own address is routed to loopback";
	EXPECT_EQ(th_drain_ingress(st), 1u);
	EXPECT_EQ(udp_read(u, 2000), d);
	th_close(st, u);
}

TEST_F(L3, UdpToTheLoopbackRangeIsDelivered)
{
	int u = th_udp_open(st, 6902);
	std::vector<uint8_t> d = {7};
	th_udp_sendto(st, u, d.data(), d.size(), "127.1.2.3", 6902);
	take_raw_frames();
	th_drain_ingress(st);
	EXPECT_EQ(udp_read(u, 2000), d) << "all of 127/8 is local";
	th_close(st, u);
}

// ------------------------------------------------------------------ ARP

class ArpMore : public L3
{
      protected:
	const Mac nb{0x02, 0, 0, 0, 0, 0x44};
	size_t requests_for(const std::vector<std::vector<uint8_t>> &v, const char *target)
	{
		return (size_t)std::count_if(
		    v.begin(), v.end(), [&](auto &f) { return is_arp_request_for(f, ip(target)); });
	}
	void reply_from(const char *who, const Mac &mac)
	{
		inject_frame(build_arp_reply(mac, ip(who), stack_mac, ip(STACK_IP)));
	}
	void run(uint64_t ms)
	{
		for (uint64_t t = 0; t < ms; t += 50) {
			fake_clock_advance(50);
			guarded("timers", [this] {
				th_run_timers(st);
				th_pump_tx(st);
				return 0;
			});
		}
	}
};

TEST_F(ArpMore, ReplyStopsTheRetries)
{
	int u = th_udp_open(st, 7100);
	std::vector<uint8_t> d = {1};
	th_udp_sendto(st, u, d.data(), d.size(), "10.0.0.30", 7101);
	ASSERT_EQ(requests_for(take_raw_frames(), "10.0.0.30"), 1u);
	reply_from("10.0.0.30", nb);
	auto out = take_raw_frames();
	ASSERT_EQ(out.size(), 1u) << "the queued datagram";
	run(5000);
	EXPECT_EQ(requests_for(take_raw_frames(), "10.0.0.30"), 0u)
	    << "the retry timer must be cancelled when the reply arrives";
	th_close(st, u);
}

TEST_F(ArpMore, LaterRepliesDontReplaceAResolvedMac)
{
	int u = th_udp_open(st, 7102);
	std::vector<uint8_t> d = {1};
	th_udp_sendto(st, u, d.data(), d.size(), "10.0.0.31", 7103);
	take_raw_frames();
	reply_from("10.0.0.31", nb);
	take_raw_frames();
	Mac other{0x02, 0, 0, 0, 0, 0x99};
	reply_from("10.0.0.31", other); // unsolicited: ignored
	th_udp_sendto(st, u, d.data(), d.size(), "10.0.0.31", 7103);
	auto out = take_raw_frames();
	ASSERT_EQ(out.size(), 1u);
	EXPECT_TRUE(std::equal(nb.begin(), nb.end(), out[0].begin()))
	    << "an unsolicited reply must not redirect our traffic";
	th_close(st, u);
}

TEST_F(ArpMore, PendingQueueIsBoundedAndOverflowIsReleased)
{
	constexpr size_t CAP = 32; // ARP_NODE_PENDING_PKT_CAP
	int u = th_udp_open(st, 7104);
	for (size_t i = 0; i < CAP + 8; i++) {
		std::vector<uint8_t> d = {(uint8_t)i};
		th_udp_sendto(st, u, d.data(), d.size(), "10.0.0.32", 7105);
	}
	auto first = take_raw_frames();
	EXPECT_EQ(requests_for(first, "10.0.0.32"), 1u);
	reply_from("10.0.0.32", nb);
	auto out = take_raw_frames();
	EXPECT_EQ(out.size(), CAP) << "only what fits the pending queue goes out";
	for (size_t i = 0; i < out.size(); i++)
		EXPECT_EQ(out[i][42], (uint8_t)i) << "in order, the oldest kept";
	th_close(st, u);
	// the fixture checks that the 8 dropped datagrams went back to the pool
}

TEST_F(ArpMore, RequestForTheLoopbackAddressIsIgnored)
{
	inject_frame(build_arp_request(peer_mac, ip(PEER_IP), ip("127.0.0.1")));
	EXPECT_TRUE(take_raw_frames().empty());
}

TEST_F(ArpMore, GivingUpReleasesEveryQueuedPacket)
{
	int u = th_udp_open(st, 7106);
	for (int i = 0; i < 10; i++) {
		std::vector<uint8_t> d(100, (uint8_t)i);
		th_udp_sendto(st, u, d.data(), d.size(), "10.0.0.33", 7107);
	}
	take_raw_frames();
	run(4500); // initial request + 3 retries, then the entry is dropped
	auto later = take_raw_frames();
	EXPECT_EQ(requests_for(later, "10.0.0.33"), 3u);
	th_close(st, u);
	// fixture: all 10 datagrams must be back in the pool
}
