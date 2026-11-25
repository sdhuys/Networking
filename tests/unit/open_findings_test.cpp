// Tests for review findings that are still open. They describe the RFC behaviour and are
// expected to fail until the finding is fixed, so they're disabled by default.
// Run them with:   ./unit_tests --gtest_also_run_disabled_tests --gtest_filter='OpenFinding*'
// When one passes, move it to the suite it belongs to (without the DISABLED_ prefix) so it
// guards against regressions. Fixed and moved so far: 20, 21, 26, 30 (window_test.cpp,
// network_test.cpp).

#include "stack_fixture.hpp"

class OpenFinding : public StackTest
{
      protected:
	int l = -1;
	PeerConn c;
	void SetUp() override
	{
		StackTest::SetUp();
		l = listen(9000);
		c = open_passive(l, 9000, 44000);
	}
};

// Finding 22: an in-window SYN on a synchronized connection gets a challenge ACK
// (RFC 5961 4.2), not a reset.
// On main this test currently CRASHES the whole binary: the RST_UNEXPECTED_SYN branch in
// process_tcp_segment hands p to out_d->pkt_snd_now without retain_pkt, so the packet is
// released twice and release_pkt's assert fires. Run it on its own.
TEST_F(OpenFinding, DISABLED_F22_InWindowSynGetsChallengeAck)
{
	TcpSegment s = seg_for(c, SYN);
	s.seq = c.peer_nxt + 10;
	inject(s);
	TcpSegment a = next_out("challenge ACK");
	EXPECT_EQ(a.flags, ACK) << a.describe();
	EXPECT_EQ(info(c).state, TH_ESTABLISHED);
}

// Finding 23: TSecr must echo the most recent TSval from the peer (RFC 7323 4.3).
TEST_F(OpenFinding, DISABLED_F23_TimestampsEchoTheLatestPeerValue)
{
	ASSERT_TRUE(c.ts);
	TcpSegment s = seg_for(c, ACK | PSH);
	s.payload = pattern(100);
	s.opts.ts->first = 777777;
	inject(s);
	c.peer_nxt += 100;
	advance(500);
	TcpSegment a = next_out("ACK");
	ASSERT_TRUE(a.opts.ts.has_value());
	EXPECT_EQ(a.opts.ts->second, 777777u);
	app_read(c, 100);
}

// Finding 24: the RTO must come from measured RTT (RFC 6298), not stay at 1 s.
TEST_F(OpenFinding, DISABLED_F24_RtoFollowsMeasuredRtt)
{
	for (int i = 0; i < 20; i++) {
		app_write(c, pattern(100, i));
		for (auto &s : drain_out())
			peer_saw(c, s);
		advance(10); // 10 ms RTT
		peer_send(c, ACK);
	}
	EXPECT_LT(info(c).rto_ms, 1000u)
	    << "RFC 6298 allows a 1 s minimum; a measured RTO below that is optional";
	EXPECT_GE(info(c).rto_ms, 200u);
}

// Finding 28: data on a SYN is acknowledged, so it must also be delivered.
TEST_F(OpenFinding, DISABLED_F28_DataOnSynIsDelivered)
{
	PeerConn n;
	n.stack_port = 9000;
	n.peer_port = 44100;
	n.peer_nxt = 1;
	TcpSegment syn = seg_for(n, SYN);
	syn.payload = pattern(50);
	inject(syn);
	n.peer_nxt += 51;
	TcpSegment sa = next_out("SYN-ACK");
	if (sa.ack == 52u) { // the data was acknowledged
		n.stack_nxt = sa.seq + 1;
		peer_send(n, ACK);
		auto fd = call_with_timeout<int>([this] { return th_accept(st, l); }, 2000);
		ASSERT_TRUE(fd.has_value());
		n.fd = *fd;
		EXPECT_EQ(app_read(n, 50), pattern(50));
	} else {
		EXPECT_EQ(sa.ack, 2u) << "if the data isn't stored it must not be acknowledged";
	}
}

// Finding 32: FIN_WAIT_2 must not last forever if the peer never sends its FIN.
TEST_F(OpenFinding, DISABLED_F32_FinWait2TimesOut)
{
	int fd = c.fd;
	guarded("end_send", [this, fd] { return th_end_send(st, fd); });
	for (auto &s : drain_out())
		peer_saw(c, s);
	peer_send(c, ACK);
	ASSERT_EQ(info(c).state, TH_FIN_WAIT_2);
	advance(10 * 60 * 1000, 1000);
	EXPECT_FALSE(exists(c));
}

// Finding 33: a window smaller than one MSS still takes data (RFC 1122 4.2.3.4).
TEST_F(OpenFinding, DISABLED_F33_DataFlowsIntoASmallWindow)
{
	PeerConn p = open_passive(l, 9000, 44200, [] {
		TcpOptions o;
		o.mss = 1460;
		return o;
	}());
	p.peer_window = 500;
	peer_send(p, ACK);
	app_write(p, pattern(2000)); // more than the window
	advance(6000);
	// count distinct bytes: retransmissions of the same range don't count twice
	uint32_t first = p.stack_iss + 1, end = first;
	for (auto &s : drain_out())
		if (!s.payload.empty() && seq_lt(end, s.seq + (uint32_t)s.payload.size())
		    && seq_le(first, s.seq))
			end = s.seq + (uint32_t)s.payload.size();
	EXPECT_EQ(end - first, 500u)
	    << "fill the 500-byte window (RFC 1122 4.2.3.4: usable window >= half the max)";
}

// Finding 34: an ACK to a listener that never sent a cookie should get a RST.
TEST_F(OpenFinding, DISABLED_F34_StrayAckToListenerGetsRst)
{
	PeerConn n;
	n.stack_port = 9000;
	n.peer_port = 44300;
	n.peer_nxt = 77;
	n.stack_nxt = 123456;
	peer_send(n, ACK);
	TcpSegment r = next_out("RST (RFC 9293 3.10.7.2)");
	EXPECT_TRUE(r.flags & RST);
	EXPECT_EQ(r.seq, 123456u);
}

// Finding 27: in SYN_SENT a RST is acceptable only if it acknowledges our SYN
// (RFC 9293 3.10.7.3). This one acks something else and must be ignored.
TEST_F(OpenFinding, DISABLED_F27_RstWithWrongAckInSynSentIsIgnored)
{
	Pending<int> connect([this] { return th_connect(st, 50003, PEER_IP, 82); });
	TcpSegment syn = wait_out("SYN");
	PeerConn s;
	s.stack_port = 50003;
	s.peer_port = 82;
	s.stack_nxt = syn.seq + 1000; // not our SYN
	peer_send(s, RST | ACK);
	EXPECT_FALSE(connect.wait(50).has_value()) << "connect gave up on an unacceptable RST";
	EXPECT_TRUE(exists(s));
	s.stack_nxt = syn.seq + 1; // now the right one, so the connect thread ends
	peer_send(s, RST | ACK);
	connect.wait(2000);
}

// Finding 27 (second part): a bare ACK of our SYN, without a SYN, must be dropped
// (RFC 9293 3.10.7.3: "if [...] neither the SYN or RST bits is set, drop the segment").
// Today it marks the SYN as acked, so the real SYN-ACK that follows is a duplicate ACK and
// the connection never completes.
TEST_F(OpenFinding, DISABLED_F27_BareAckOfOurSynDoesNotHangTheConnect)
{
	Pending<int> connect([this] { return th_connect(st, 50004, PEER_IP, 83); });
	TcpSegment syn = wait_out("SYN");
	PeerConn s;
	s.stack_port = 50004;
	s.peer_port = 83;
	s.peer_iss = s.peer_nxt = 7000;
	s.stack_nxt = syn.seq + 1;
	peer_send(s, ACK); // acks our SYN, but no SYN of its own
	drain_out();
	TcpSegment sa = seg_for(s, SYN | ACK);
	sa.opts = linux_syn_options();
	inject(sa);
	auto fd = connect.wait(2000);
	EXPECT_TRUE(fd.has_value() && *fd >= 0)
	    << "the SYN-ACK after a bare ACK must complete the handshake";
	if (!fd)
		connect.wait(60000); // let it give up so the thread ends
}

// ---- finding 25: congestion control (RFC 5681, RFC 6582) ----

class OpenCongestion : public OpenFinding
{
      protected:
	std::vector<TcpSegment> take_data()
	{
		std::vector<TcpSegment> v;
		for (auto &s : drain_out()) {
			peer_saw(c, s);
			if (!s.payload.empty())
				v.push_back(s);
		}
		return v;
	}
	void ack_up_to(uint32_t ack, std::vector<std::pair<uint32_t, uint32_t>> sacks = {})
	{
		TcpSegment a = seg_for(c, ACK);
		a.ack = ack;
		a.opts.sacks = std::move(sacks);
		inject(a);
	}
	// three duplicate ACKs for `hole`, SACKing what came after it
	void three_dupacks(uint32_t hole, uint32_t sacked_from, uint32_t sacked_to)
	{
		for (int i = 0; i < 3; i++)
			ack_up_to(hole, {{sacked_from, sacked_to}});
	}
};

// 25(a): an RTO must set ssthresh to max(FlightSize / 2, 2 * MSS) (RFC 5681 eq. 4).
TEST_F(OpenCongestion, DISABLED_F25a_RtoHalvesSsthresh)
{
	app_write(c, pattern(10 * 1400, 1));
	take_data();
	uint32_t flight = c.stack_nxt - (c.stack_iss + 1);
	advance(1000); // RTO
	drain_out();
	th_conn_info i = info(c);
	EXPECT_EQ(i.cwnd, i.snd_mss) << "loss window is one segment";
	EXPECT_LE(i.ssthresh, std::max(flight / 2, 2 * i.snd_mss))
	    << "ssthresh left at " << i.ssthresh << ": slow start will run back into the loss";
	ack_up_to(c.stack_nxt);
	drain_out();
}

// 25(b): congestion avoidance grows cwnd by about one MSS per cwnd of ACKed data,
// also when every ACK covers only a little (RFC 5681 eq. 3 / RFC 3465).
TEST_F(OpenCongestion, DISABLED_F25b_CongestionAvoidanceGrowsWithSmallAcks)
{
	// get into congestion avoidance: fast retransmit, then a full ACK
	app_write(c, pattern(10 * 1400, 2));
	auto segs = take_data();
	ASSERT_GE(segs.size(), 5u);
	ack_up_to(segs[1].seq);
	three_dupacks(segs[1].seq, segs[2].seq, c.stack_nxt);
	take_data();
	ack_up_to(c.stack_nxt);
	take_data();
	th_conn_info start = info(c);
	ASSERT_LT(start.ssthresh, 0xFFFFFFFFu);

	// keep a cwnd's worth in flight and ACK it 100 bytes at a time
	uint32_t base = c.stack_nxt;
	app_write(c, pattern(start.cwnd, 3));
	take_data();
	for (uint32_t acked = 100; acked <= start.cwnd; acked += 100)
		ack_up_to(base + acked);
	take_data();
	EXPECT_GE(info(c).cwnd, start.cwnd + start.snd_mss / 2)
	    << "a full cwnd of small ACKs must grow cwnd by about one MSS (was " << start.cwnd
	    << ", now " << info(c).cwnd << ")";
}

// 25(c): NewReno. A partial ACK during fast recovery retransmits the next hole at once
// and stays in recovery (RFC 6582 3.2 step 3).
TEST_F(OpenCongestion, DISABLED_F25c_PartialAckRetransmitsTheNextHole)
{
	app_write(c, pattern(10 * 1400, 4));
	auto segs = take_data();
	ASSERT_GE(segs.size(), 8u);
	// segments 1 and 3 are lost; 0, 2, 4.. arrive
	ack_up_to(segs[1].seq);
	three_dupacks(segs[1].seq, segs[2].seq, segs[3].seq);
	auto r1 = take_data();
	ASSERT_FALSE(r1.empty());
	EXPECT_EQ(r1[0].seq, segs[1].seq) << "fast retransmit of the first hole";

	// the retransmission arrives: ACK up to the second hole (a partial ACK)
	ack_up_to(segs[3].seq, {{segs[4].seq, c.stack_nxt}});
	auto r2 = take_data();
	bool resent = false;
	for (auto &s : r2)
		if (s.seq == segs[3].seq)
			resent = true;
	EXPECT_TRUE(resent) << "the partial ACK must retransmit the next hole without waiting "
			       "for three more duplicate ACKs or an RTO";
	ack_up_to(c.stack_nxt);
	drain_out();
}

// 25(d): after an RTO everything in flight counts as lost. Once the first retransmission
// is ACKed, the next unacked segment is resent before new data (go-back-N).
TEST_F(OpenCongestion, DISABLED_F25d_AfterAnRtoTheNextUnackedSegmentIsResentFirst)
{
	app_write(c, pattern(4 * 1400, 5));
	auto segs = take_data();
	ASSERT_GE(segs.size(), 3u);
	advance(1000); // RTO: nothing was acked
	auto r = take_data();
	ASSERT_FALSE(r.empty());
	EXPECT_EQ(r[0].seq, segs[0].seq);
	ack_up_to(segs[1].seq); // only the first segment arrived
	auto next = take_data();
	ASSERT_FALSE(next.empty()) << "cwnd grew to 2: something must be sent";
	EXPECT_EQ(next[0].seq, segs[1].seq) << "the second segment is still missing and must be "
					       "resent now, not after its own RTO";
	ack_up_to(c.stack_nxt);
	drain_out();
}
