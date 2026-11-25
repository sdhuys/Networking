// Connection setup: passive and active open, option negotiation, SYN retransmission,
// half-open limits and resets for closed ports.

#include "stack_fixture.hpp"

class Handshake : public StackTest
{
};

TEST_F(Handshake, PassiveOpenSynAckCarriesOurOptions)
{
	int l = listen(9000);
	PeerConn c;
	c.stack_port = 9000;
	c.peer_port = 40000;
	c.peer_nxt = 1000;

	TcpSegment syn = seg_for(c, SYN);
	syn.opts = linux_syn_options();
	inject(syn);

	TcpSegment sa = next_out("SYN-ACK");
	EXPECT_EQ(sa.flags, SYN | ACK) << sa.describe();
	EXPECT_EQ(sa.ack, 1001u) << "SYN-ACK must acknowledge the SYN";
	EXPECT_EQ(sa.src_port, 9000);
	EXPECT_EQ(sa.dst_port, 40000);
	EXPECT_EQ(sa.dst_mac, peer_mac);
	ASSERT_TRUE(sa.opts.mss.has_value()) << "SYN-ACK should announce an MSS";
	EXPECT_LE(*sa.opts.mss, 1460) << "MSS above what a 1500-byte MTU allows";
	EXPECT_TRUE(sa.opts.sack_permitted) << "peer offered SACK";
	ASSERT_TRUE(sa.opts.ts.has_value()) << "peer offered timestamps";
	EXPECT_EQ(sa.opts.ts->second, syn.opts.ts->first) << "TSecr must echo the SYN's TSval";
	EXPECT_TRUE(sa.opts.wscale.has_value()) << "peer offered window scaling";
	EXPECT_EQ(sa.payload.size(), 0u);
	(void)l;
}

TEST_F(Handshake, PassiveOpenCompletesAndAccepts)
{
	int l = listen(9000);
	PeerConn c = open_passive(l, 9000, 40000);
	EXPECT_GE(c.fd, 0);
	th_conn_info i = info(c);
	EXPECT_EQ(i.state, TH_ESTABLISHED);
	EXPECT_TRUE(i.sack_enabled);
	EXPECT_TRUE(i.ts_enabled);
	EXPECT_TRUE(i.wscale_enabled);
	EXPECT_EQ(i.irs, 1000u);
	EXPECT_EQ(i.rcv_nxt, 1001u);
	expect_nothing_out("the final ACK of a handshake needs no reply");
}

TEST_F(Handshake, PassiveOpenWithoutOptionsFallsBackToDefaults)
{
	int l = listen(9000);
	TcpOptions none;
	PeerConn c = open_passive(l, 9000, 40001, none);
	th_conn_info i = info(c);
	EXPECT_EQ(i.state, TH_ESTABLISHED);
	EXPECT_FALSE(i.sack_enabled);
	EXPECT_FALSE(i.ts_enabled);
	EXPECT_FALSE(i.wscale_enabled);
	EXPECT_EQ(i.snd_mss, 536u) << "RFC 9293 3.7.1: no MSS option means 536";
}

TEST_F(Handshake, SynAckWithoutPeerTimestampsCarriesNone)
{
	listen(9000);
	PeerConn c;
	c.stack_port = 9000;
	c.peer_port = 40002;
	c.peer_nxt = 1;
	TcpSegment syn = seg_for(c, SYN);
	syn.opts.mss = 1460;
	inject(syn);
	TcpSegment sa = next_out("SYN-ACK");
	EXPECT_FALSE(sa.opts.ts.has_value())
	    << "timestamps only if the peer's SYN had them (RFC 7323 3.2)";
	EXPECT_FALSE(sa.opts.sack_permitted) << "SACK-permitted only if the peer's SYN had it";
	EXPECT_FALSE(sa.opts.wscale.has_value())
	    << "window scale only if the peer's SYN had it (RFC 7323 2.2)";
	EXPECT_LE(sa.window, 65535);
}

TEST_F(Handshake, PeerMssIsClampedToOurMtu)
{
	int l = listen(9000);
	TcpOptions o = linux_syn_options();
	o.mss = 9000; // jumbo-frame peer
	PeerConn c = open_passive(l, 9000, 40003, o);
	th_conn_info i = info(c);
	EXPECT_LE(i.snd_mss, 1460u)
	    << "finding 2: never send segments larger than our own MTU allows";

	app_write(c, pattern(20000));
	for (auto &s : drain_out())
		EXPECT_LE(s.frame_len, 1514u) << s.describe();
}

TEST_F(Handshake, TinyPeerMssIsRaisedToTheFloor)
{
	int l = listen(9000);
	TcpOptions o = linux_syn_options();
	o.mss = 1;
	PeerConn c = open_passive(l, 9000, 40004, o);
	th_conn_info i = info(c);
	EXPECT_GE(i.snd_mss, 1u);
	EXPECT_LT(i.snd_mss, 1460u);

	app_write(c, pattern(500));
	auto segs = drain_out();
	ASSERT_FALSE(segs.empty());
	for (auto &s : segs)
		EXPECT_LE(s.payload.size(), 1460u)
		    << "a wrapped MSS would show up as a huge segment";
}

TEST_F(Handshake, ActiveOpenSendsSynAndCompletes)
{
	PeerConn c = open_active(50000, 80);
	th_conn_info i = info(c);
	EXPECT_EQ(i.state, TH_ESTABLISHED);
	EXPECT_EQ(i.snd_una, c.stack_iss + 1);
	EXPECT_EQ(i.rcv_nxt, c.peer_iss + 1);

	// the stack must acknowledge the SYN-ACK (RFC 9293 3.10.7.3)
	TcpSegment a = next_out("ACK of the SYN-ACK");
	EXPECT_EQ(a.flags, ACK) << a.describe();
	EXPECT_EQ(a.seq, c.stack_iss + 1);
	EXPECT_EQ(a.ack, c.peer_iss + 1);
}

TEST_F(Handshake, ActiveOpenSynOffersOptions)
{
	Pending<int> connect([this] { return th_connect(st, 50001, PEER_IP, 80); });
	TcpSegment syn = wait_out("SYN");
	EXPECT_EQ(syn.flags, SYN);
	EXPECT_EQ(syn.ack, 0u);
	ASSERT_TRUE(syn.opts.mss.has_value());
	EXPECT_LE(*syn.opts.mss, 1460);
	EXPECT_TRUE(syn.opts.sack_permitted);
	EXPECT_TRUE(syn.opts.ts.has_value());
	EXPECT_TRUE(syn.opts.wscale.has_value());

	// refuse it, so the connect thread finishes
	PeerConn c;
	c.stack_port = 50001;
	c.peer_port = 80;
	c.peer_nxt = 0;
	c.stack_nxt = syn.seq + 1;
	peer_send(c, RST | ACK);
	auto r = connect.wait(2000);
	ASSERT_TRUE(r.has_value()) << "tcp_connect still blocked after a RST";
	EXPECT_LT(*r, 0);
}

TEST_F(Handshake, ActiveOpenRefusedByRst)
{
	Pending<int> connect([this] { return th_connect(st, 50002, PEER_IP, 81); });
	TcpSegment syn = wait_out("SYN");
	PeerConn c;
	c.stack_port = 50002;
	c.peer_port = 81;
	c.stack_nxt = syn.seq + 1;
	peer_send(c, RST | ACK);
	auto r = connect.wait(2000);
	ASSERT_TRUE(r.has_value());
	EXPECT_EQ(*r, -2) << "connect returns -2 when the connection fails";
	EXPECT_FALSE(exists(c)) << "a refused connection must be removed";
}

TEST_F(Handshake, SynRetransmittedWithBackoff)
{
	Pending<int> connect([this] { return th_connect(st, 50004, PEER_IP, 83); });
	TcpSegment syn = wait_out("SYN");
	uint64_t t0 = fake_clock_ms();

	std::vector<uint64_t> gaps;
	uint64_t last = t0;
	for (int i = 0; i < 3; i++) {
		// step 10 ms at a time until the next SYN appears (max 70 s)
		bool seen = false;
		for (int ms = 0; ms < 70000 && !seen; ms += 10) {
			advance(10);
			if (pending_frames() > 0) {
				TcpSegment r = next_out("retransmitted SYN");
				EXPECT_EQ(r.flags, SYN);
				EXPECT_EQ(r.seq, syn.seq)
				    << "a retransmitted SYN keeps its sequence number";
				gaps.push_back(fake_clock_ms() - last);
				last = fake_clock_ms();
				seen = true;
			}
		}
		ASSERT_TRUE(seen) << "no SYN retransmission " << i + 1;
	}
	EXPECT_NEAR((double)gaps[0], 1000, 20)
	    << "first SYN retransmission after the initial RTO of 1 s";
	EXPECT_NEAR((double)gaps[1], 2 * gaps[0], 30) << "RTO doubles";
	EXPECT_NEAR((double)gaps[2], 2 * gaps[1], 50) << "RTO doubles";

	PeerConn c;
	c.stack_port = 50004;
	c.peer_port = 83;
	c.stack_nxt = syn.seq + 1;
	peer_send(c, RST | ACK);
	connect.wait(2000);
}

TEST_F(Handshake, ConnectGivesUpAfterSynRetries)
{
	check_pool_leaks = true;
	Pending<int> connect([this] { return th_connect(st, 50005, PEER_IP, 84); });
	wait_out("SYN");
	// 8 timeouts with doubling from 1 s, capped at 60 s: well under 10 minutes
	for (int i = 0; i < 600 && !connect.done(); i++)
		advance(1000, 50);
	auto r = connect.wait(100);
	ASSERT_TRUE(r.has_value()) << "tcp_connect never gave up on an unanswered SYN";
	EXPECT_EQ(*r, -2);
	drain_out();
}

TEST_F(Handshake, SynAckRetransmittedUntilFinalAck)
{
	listen(9000);
	PeerConn c;
	c.stack_port = 9000;
	c.peer_port = 40010;
	c.peer_nxt = 777;
	TcpSegment syn = seg_for(c, SYN);
	syn.opts = linux_syn_options();
	inject(syn);
	TcpSegment sa1 = next_out("SYN-ACK");

	advance(1100);
	TcpSegment sa2 = next_out("retransmitted SYN-ACK after the RTO");
	EXPECT_EQ(sa2.flags, SYN | ACK);
	EXPECT_EQ(sa2.seq, sa1.seq);
	EXPECT_EQ(sa2.ack, 778u);
}

TEST_F(Handshake, DuplicateSynResendsSynAckImmediately)
{
	listen(9000);
	PeerConn c;
	c.stack_port = 9000;
	c.peer_port = 40011;
	c.peer_nxt = 50;
	TcpSegment syn = seg_for(c, SYN);
	syn.opts = linux_syn_options();
	inject(syn);
	TcpSegment sa1 = next_out("SYN-ACK");

	inject(syn); // the peer retransmits its SYN (our SYN-ACK was lost)
	TcpSegment sa2 = next_out("SYN-ACK in reply to the duplicate SYN");
	EXPECT_EQ(sa2.flags, SYN | ACK);
	EXPECT_EQ(sa2.seq, sa1.seq) << "same connection, same ISS";
	EXPECT_EQ(info(c).rto_ms, 1000u) << "a duplicate SYN is not a timeout: no backoff";
}

TEST_F(Handshake, HalfOpenConnectionIsReapedAfterRetries)
{
	listen(9000);
	PeerConn c;
	c.stack_port = 9000;
	c.peer_port = 40012;
	c.peer_nxt = 50;
	TcpSegment syn = seg_for(c, SYN);
	syn.opts = linux_syn_options();
	inject(syn);
	next_out("SYN-ACK");
	ASSERT_TRUE(exists(c));
	for (int i = 0; i < 600 && exists(c); i++)
		advance(1000, 50);
	EXPECT_FALSE(exists(c))
	    << "finding 13: a half-open connection that never completes must be removed";
	drain_out();
}

TEST_F(Handshake, SynToClosedPortGetsRstAck)
{
	PeerConn c;
	c.stack_port = 9999; // nothing listens here
	c.peer_port = 40020;
	c.peer_nxt = 12345;
	TcpSegment syn = seg_for(c, SYN);
	inject(syn);
	TcpSegment r = next_out("RST");
	EXPECT_EQ(r.flags, RST | ACK) << r.describe();
	EXPECT_EQ(r.seq, 0u);
	EXPECT_EQ(r.ack, 12346u) << "RFC 9293 3.10.7.1: ack = SEG.SEQ + SEG.LEN";
}

TEST_F(Handshake, AckToClosedPortGetsRstWithItsAckAsSeq)
{
	PeerConn c;
	c.stack_port = 9999;
	c.peer_port = 40021;
	c.peer_nxt = 10;
	c.stack_nxt = 424242;
	peer_send(c, ACK);
	TcpSegment r = next_out("RST");
	EXPECT_EQ(r.flags, RST) << r.describe();
	EXPECT_EQ(r.seq, 424242u) << "RFC 9293 3.10.7.1: seq = SEG.ACK";
}

TEST_F(Handshake, RstToClosedPortGetsNoReply)
{
	PeerConn c;
	c.stack_port = 9999;
	c.peer_port = 40022;
	c.peer_nxt = 10;
	peer_send(c, RST);
	expect_nothing_out("never answer a RST with a RST");
}

TEST_F(Handshake, AcceptQueueFullDropsNewSyns)
{
	int l = listen(9100);
	(void)l;
	// complete 128 handshakes without calling accept (default backlog)
	for (int i = 0; i < 128; i++) {
		PeerConn c;
		c.stack_port = 9100;
		c.peer_port = (uint16_t)(20000 + i);
		c.peer_nxt = 100;
		TcpSegment syn = seg_for(c, SYN);
		inject(syn);
		c.peer_nxt++;
		TcpSegment sa = next_out("SYN-ACK");
		c.stack_nxt = sa.seq + 1;
		peer_send(c, ACK);
	}
	PeerConn extra;
	extra.stack_port = 9100;
	extra.peer_port = 30000;
	extra.peer_nxt = 100;
	inject(seg_for(extra, SYN));
	expect_nothing_out("the accept queue is full: drop the SYN, the peer retries");
	EXPECT_FALSE(exists(extra));
}
