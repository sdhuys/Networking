// Window validation and window bookkeeping:
// - the RFC 9293 acceptability test and the ACK every rejected segment gets (finding 21),
//   with RFC 5961 rate limiting and its exemptions
// - ACKs processed while our receive window is 0 (finding 44), without probes counting
//   as duplicate ACKs
// - window scale negotiation on both open paths (finding 20, RFC 7323 2.2)
// - SND.WL1 / SND.WL2: a reordered old segment must not overwrite the send window (finding 26)

#include "stack_fixture.hpp"

namespace
{
constexpr uint32_t BUFFER = 0x80000; // TCP_DEFAULT_BUFFER_SIZE: our receive buffer, 512 KB
constexpr uint8_t OUR_SCALE = 4;     // tcp_calc_wndw_scale(512 KB)
constexpr uint8_t LINUX_SCALE = 7;   // what linux_syn_options() offers
} // namespace

class Window : public StackTest
{
      protected:
	int l = -1;
	PeerConn c;

	void SetUp() override
	{
		StackTest::SetUp();
		l = listen(9000);
		c = open_passive(l, 9000, 45000);
	}

	uint32_t our_window_bytes()
	{
		return (uint32_t)info(c).rcv_wnd << c.stack_wscale;
	}

	// a zero-length segment at rcv_nxt - 1: what keepalives and Linux's zero-window
	// probes look like
	TcpSegment keepalive(uint32_t ack)
	{
		TcpSegment k = seg_for(c, ACK);
		k.seq = c.peer_nxt - 1;
		k.ack = ack;
		return k;
	}

	size_t count_acks(const std::vector<TcpSegment> &v)
	{
		size_t n = 0;
		for (auto &s : v)
			if (s.payload.empty() && (s.flags & ACK) && !(s.flags & (SYN | FIN | RST)))
				n++;
		return n;
	}

	// The peer sends data without the app reading until our advertised window is 0.
	// The segments acknowledge only up to `ack`, so the stack's own data stays unacked.
	void close_receive_window(uint32_t ack)
	{
		uint32_t mss = info(c).rcv_mss;
		for (int i = 0; i < 3000; i++) {
			uint32_t wnd = our_window_bytes();
			if (wnd == 0)
				break;
			TcpSegment d = seg_for(c, ACK);
			d.ack = ack;
			d.payload = pattern(std::min(wnd, mss), i);
			inject(d);
			c.peer_nxt += (uint32_t)d.payload.size();
			drain_out();
		}
		ASSERT_EQ(info(c).rcv_wnd, 0u) << "could not close our receive window";
		advance(300); // flush any delayed ACK
		drain_out();
	}

	// the app writes `n` bytes; returns the stack's snd_nxt after they're sent
	uint32_t send_unacked(size_t n, uint32_t seed)
	{
		app_write(c, pattern(n, seed));
		for (auto &s : drain_out())
			peer_saw(c, s);
		return c.stack_nxt;
	}
};

// ------------------------------------------------------------ acceptability test

// Finding 21: a keepalive fails the acceptability test (seq < rcv_nxt) and must be answered.
TEST_F(Window, KeepaliveGetsAnAck)
{
	inject(keepalive(c.stack_nxt));
	TcpSegment a = next_out("ACK for a keepalive (RFC 9293 3.10.7.4)");
	EXPECT_EQ(a.flags, ACK) << a.describe();
	EXPECT_EQ(a.ack, c.peer_nxt);
	EXPECT_EQ(a.seq, c.stack_nxt);
	EXPECT_EQ(info(c).state, TH_ESTABLISHED);
}

TEST_F(Window, ZeroLengthSegmentBeyondTheWindowIsAcked)
{
	TcpSegment s = seg_for(c, ACK);
	s.seq = c.peer_nxt + our_window_bytes() + 100;
	inject(s);
	TcpSegment a = next_out("ACK for a segment beyond the window");
	EXPECT_EQ(a.ack, c.peer_nxt) << "the ACK states what we really expect";
	EXPECT_EQ(info(c).rcv_nxt, c.peer_nxt);
}

TEST_F(Window, DataBeyondTheWindowIsAckedAndDropped)
{
	TcpSegment s = seg_for(c, ACK | PSH);
	s.seq = c.peer_nxt + our_window_bytes();
	s.payload = pattern(100);
	inject(s);
	TcpSegment a = next_out("ACK for data beyond the window");
	EXPECT_EQ(a.ack, c.peer_nxt);
	EXPECT_EQ(info(c).rcv_nxt, c.peer_nxt) << "data outside the window must not be accepted";
	// the next in-order byte is still the one we expect
	peer_send(c, ACK | PSH, pattern(10, 2));
	EXPECT_EQ(app_read(c, 10), pattern(10, 2));
	drain_out();
}

TEST_F(Window, DataOverlappingTheLeftEdgeIsAccepted)
{
	// a retransmission that is partly old, partly new (RFC 9293's fourth case, second clause)
	peer_send(c, ACK | PSH, pattern(100, 3));
	TcpSegment s = seg_for(c, ACK | PSH);
	s.seq = c.peer_nxt - 50;
	auto both = pattern(100, 3);
	auto fresh = pattern(80, 4);
	s.payload.assign(both.begin() + 50, both.end());
	s.payload.insert(s.payload.end(), fresh.begin(), fresh.end());
	inject(s);
	c.peer_nxt += 80;
	EXPECT_EQ(info(c).rcv_nxt, c.peer_nxt);
	auto got = app_read(c, 180);
	EXPECT_TRUE(std::equal(both.begin(), both.end(), got.begin()));
	EXPECT_TRUE(std::equal(fresh.begin(), fresh.end(), got.begin() + 100));
	drain_out();
}

// RFC 5961 7: ACKs to unacceptable segments are rate-limited per connection.
TEST_F(Window, RepliesToRejectedSegmentsAreRateLimited)
{
	inject(keepalive(c.stack_nxt));
	EXPECT_EQ(count_acks(drain_out()), 1u) << "the first one is answered";

	for (int i = 0; i < 5; i++)
		inject(keepalive(c.stack_nxt));
	EXPECT_EQ(count_acks(drain_out()), 0u) << "within 500 ms: no further replies";

	advance(500);
	drain_out();
	inject(keepalive(c.stack_nxt));
	EXPECT_EQ(count_acks(drain_out()), 1u) << "after 500 ms one reply is allowed again";
	EXPECT_EQ(info(c).state, TH_ESTABLISHED);
}

TEST_F(Window, RetransmittedFinInTimeWaitIsAlwaysAcked)
{
	// close from our side first, then the peer's FIN: we end up in TIME_WAIT
	ASSERT_EQ(th_end_send(st, c.fd), 0);
	for (auto &s : drain_out())
		peer_saw(c, s);
	peer_send(c, ACK | FIN);
	drain_out();
	ASSERT_EQ(info(c).state, TH_TIME_WAIT);

	// the peer didn't get our ACK: it retransmits its FIN several times in quick succession
	for (int i = 0; i < 3; i++) {
		TcpSegment fin = seg_for(c, ACK | FIN);
		fin.seq = c.peer_nxt - 1;
		inject(fin);
		TcpSegment a = next_out("ACK for a retransmitted FIN");
		EXPECT_EQ(a.ack, c.peer_nxt)
		    << "attempt " << i << ": FIN replies are not rate-limited";
	}
}

// ------------------------------------------------------------ zero receive window (finding 44)

TEST_F(Window, ZeroWindowProbesAreAllAnswered)
{
	close_receive_window(c.stack_nxt);
	for (int i = 0; i < 3; i++)
		inject(keepalive(c.stack_nxt));
	EXPECT_EQ(count_acks(drain_out()), 3u)
	    << "probe replies are exempt from the rate limit: the prober needs every one";
}

TEST_F(Window, ZeroWindowProbesAreNotDuplicateAcks)
{
	uint32_t old_ack = c.stack_nxt;
	send_unacked(5000, 9); // our data in flight, unacked
	close_receive_window(old_ack);
	th_conn_info before = info(c);

	// Linux's zero-window probes: seq = rcv_nxt - 1, no data, same ACK, same window.
	// On the normal path they'd pass every duplicate-ACK condition.
	for (int i = 0; i < 4; i++)
		inject(keepalive(old_ack));
	auto out = drain_out();
	for (auto &s : out)
		EXPECT_TRUE(s.payload.empty()) << "nothing may be retransmitted: " << s.describe();
	th_conn_info after = info(c);
	EXPECT_EQ(after.cwnd, before.cwnd) << "probes started a fast recovery";
	EXPECT_EQ(after.snd_una, before.snd_una);
}

TEST_F(Window, PeersRealDupAcksStillCountWhileOurWindowIsZero)
{
	uint32_t old_ack = c.stack_nxt;
	send_unacked(5000, 10);
	close_receive_window(old_ack);
	th_conn_info before = info(c);

	// the peer probed our window with one byte, so its later pure ACKs carry
	// seq = rcv_nxt + 1. Three of those acking nothing new are real duplicate ACKs.
	for (int i = 0; i < 3; i++) {
		TcpSegment d = seg_for(c, ACK);
		d.seq = c.peer_nxt + 1;
		d.ack = old_ack;
		inject(d);
	}
	bool retransmitted = false;
	for (auto &s : drain_out())
		if (!s.payload.empty() && s.seq == old_ack)
			retransmitted = true;
	EXPECT_TRUE(retransmitted) << "three duplicate ACKs must trigger a fast retransmit";
	EXPECT_LT(info(c).ssthresh, before.ssthresh) << "fast recovery lowers ssthresh";
}

// ------------------------------------------------------------ window scaling (finding 20)

TEST_F(Window, PassiveOpenNegotiatesScaling)
{
	PeerConn n;
	n.stack_port = 9000;
	n.peer_port = 45100;
	n.peer_iss = n.peer_nxt = 2000;
	TcpSegment syn = seg_for(n, SYN);
	syn.opts = linux_syn_options();
	syn.window = 1000;
	inject(syn);
	n.peer_nxt++;
	TcpSegment sa = next_out("SYN-ACK");
	ASSERT_TRUE(sa.opts.wscale.has_value()) << "the peer offered scaling, so we must too";
	EXPECT_EQ(*sa.opts.wscale, OUR_SCALE);
	EXPECT_EQ(sa.window, 65535) << "RFC 7323 2.2: a SYN's window is never scaled (512 KB "
				       "free, capped at 65535)";
	EXPECT_EQ(info(n).snd_wnd, 1000u) << "the peer's SYN window must not be scaled";

	n.stack_iss = sa.seq;
	n.stack_nxt = sa.seq + 1;
	n.peer_window = 1000;
	peer_send(n, ACK);
	EXPECT_EQ(info(n).snd_wnd, 1000u << LINUX_SCALE)
	    << "after the handshake the peer's window field is scaled by its wscale";
	EXPECT_TRUE(info(n).wscale_enabled);
}

TEST_F(Window, PassiveOpenWithoutPeerScalingUsesNone)
{
	PeerConn n;
	n.stack_port = 9000;
	n.peer_port = 45101;
	n.peer_iss = n.peer_nxt = 3000;
	TcpOptions o = linux_syn_options();
	o.wscale.reset();
	TcpSegment syn = seg_for(n, SYN);
	syn.opts = o;
	inject(syn);
	n.peer_nxt++;
	TcpSegment sa = next_out("SYN-ACK");
	EXPECT_FALSE(sa.opts.wscale.has_value()) << "no scale option unless the peer sent one";
	n.stack_iss = sa.seq;
	n.stack_nxt = sa.seq + 1;
	n.peer_window = 30000;
	peer_send(n, ACK);
	EXPECT_FALSE(info(n).wscale_enabled);
	EXPECT_EQ(info(n).snd_wnd, 30000u) << "the peer's window must be used unscaled";

	// our own window field must be unscaled too: 512 KB free, capped at 65535,
	// not 512 KB >> 4 = 32768
	peer_send(n, ACK | PSH, pattern(10));
	advance(300);
	bool saw_ack = false;
	for (auto &s : drain_out())
		if (s.dst_port == n.peer_port) {
			saw_ack = true;
			EXPECT_GE(s.window, 65535 - 10) << s.describe();
		}
	EXPECT_TRUE(saw_ack);
}

TEST_F(Window, ActiveOpenAppliesPeerScale)
{
	PeerConn a = open_active(51000, 80); // peer offers wscale 7
	drain_out();
	EXPECT_EQ(info(a).snd_wnd, 65535u) << "the SYN-ACK's window is not scaled";
	a.peer_window = 4000; // scaled: 512000 bytes; unscaled: 4000 bytes
	peer_send(a, ACK);
	EXPECT_EQ(info(a).snd_wnd, 4000u << LINUX_SCALE);
	app_write(a, pattern(20000));
	size_t bytes = 0;
	for (auto &s : drain_out())
		bytes += s.payload.size();
	EXPECT_GT(bytes, 4000u) << "the peer's window field must be scaled by its wscale";
}

TEST_F(Window, ActiveOpenSynCarriesAnUnscaledWindow)
{
	Pending<int> connect([this] { return th_connect(st, 51001, PEER_IP, 81); });
	TcpSegment syn = wait_out("SYN");
	ASSERT_TRUE(syn.opts.wscale.has_value());
	EXPECT_EQ(syn.window, 65535) << "RFC 7323 2.2: a SYN's window is never scaled";
	// refuse, so the connect thread ends
	PeerConn r;
	r.stack_port = 51001;
	r.peer_port = 81;
	r.stack_nxt = syn.seq + 1;
	peer_send(r, RST | ACK);
	connect.wait(2000);
}

TEST_F(Window, ActiveOpenWithoutPeerScalingUsesNone)
{
	TcpOptions o = linux_syn_options();
	o.wscale.reset();
	PeerConn a = open_active(51002, 82, o);
	auto out = drain_out(); // our ACK of the SYN-ACK
	ASSERT_FALSE(out.empty());
	EXPECT_FALSE(info(a).wscale_enabled);
	EXPECT_EQ(out.back().window, 65535)
	    << "without scaling our window field is the free space capped at 65535, not >> 4";
	a.peer_window = 4000;
	peer_send(a, ACK);
	EXPECT_EQ(info(a).snd_wnd, 4000u);
}

// ------------------------------------------------------------ SND.WL1 / SND.WL2 (finding 26)

TEST_F(Window, ReorderedOlderSegmentDoesNotOverwriteTheWindow)
{
	// the peer sends A then B; B arrives first
	TcpSegment a = seg_for(c, ACK | PSH);
	a.payload = pattern(10, 1);
	a.window = 100; // the peer's window when it sent A
	TcpSegment b = seg_for(c, ACK | PSH);
	b.seq = a.seq + 10;
	b.payload = pattern(10, 2);
	b.window = 60000; // later, its application had read
	inject(b);
	EXPECT_EQ(info(c).snd_wnd, 60000u << LINUX_SCALE);
	inject(a); // older (lower seq): its window is stale
	c.peer_nxt += 20;
	EXPECT_EQ(info(c).snd_wnd, 60000u << LINUX_SCALE)
	    << "an older segment overwrote the send window (RFC 9293 3.10.7.4, SND.WL1)";
	EXPECT_EQ(app_read(c, 20).size(), 20u);
	drain_out();
}

TEST_F(Window, WindowUpdateWithSameSeqAndAckIsApplied)
{
	// a pure window update carries the same seq and ack as the previous segment;
	// RFC 9293 allows it (SND.WL1 == SEG.SEQ and SND.WL2 <= SEG.ACK)
	c.peer_window = 100;
	peer_send(c, ACK);
	EXPECT_EQ(info(c).snd_wnd, 100u << LINUX_SCALE);
	c.peer_window = 50000;
	peer_send(c, ACK);
	EXPECT_EQ(info(c).snd_wnd, 50000u << LINUX_SCALE);
}

TEST_F(Window, AckWithAHigherAckNumberUpdatesTheWindow)
{
	send_unacked(1000, 11);
	uint32_t acked = c.stack_nxt;
	TcpSegment s = seg_for(c, ACK);
	s.ack = acked;
	s.window = 1234;
	inject(s);
	EXPECT_EQ(info(c).snd_una, acked);
	EXPECT_EQ(info(c).snd_wnd, 1234u << LINUX_SCALE);
}

TEST_F(Window, StateOfOurBufferIsConsistentAfterHandshake)
{
	// sanity check the constants this file relies on
	EXPECT_EQ(c.stack_wscale, OUR_SCALE);
	EXPECT_EQ(our_window_bytes(), BUFFER);
}
