// Connection teardown: active, passive and simultaneous close, TIME_WAIT, resets,
// and closing a listener.

#include "stack_fixture.hpp"

class Close : public StackTest
{
      protected:
	int l = -1;
	PeerConn c;

	void SetUp() override
	{
		StackTest::SetUp();
		l = listen(9000);
		c = open_passive(l, 9000, 42000);
	}

	int end_send()
	{
		int fd = c.fd;
		return guarded("tcp_end_send", [this, fd] { return th_end_send(st, fd); });
	}

	TcpSegment expect_fin()
	{
		TcpSegment f = next_out("FIN");
		EXPECT_TRUE(f.flags & FIN) << f.describe();
		EXPECT_TRUE(f.flags & ACK) << f.describe();
		peer_saw(c, f);
		return f;
	}
};

TEST_F(Close, ActiveCloseGoesThroughTimeWait)
{
	ASSERT_EQ(end_send(), 0);
	TcpSegment fin = expect_fin();
	EXPECT_EQ(fin.seq, c.stack_iss + 1) << "no data was sent, FIN is the first byte";
	EXPECT_EQ(info(c).state, TH_FIN_WAIT_1);

	peer_send(c, ACK);
	EXPECT_EQ(info(c).state, TH_FIN_WAIT_2);

	peer_send(c, FIN | ACK);
	TcpSegment a = next_out("ACK of the peer's FIN");
	EXPECT_EQ(a.ack, c.peer_nxt);
	th_conn_info i = info(c);
	EXPECT_EQ(i.state, TH_TIME_WAIT);
	EXPECT_TRUE(i.in_time_wait_table);

	advance(59000, 100);
	EXPECT_TRUE(exists(c)) << "TIME_WAIT lasts 60 s";
	advance(2000, 100);
	EXPECT_FALSE(exists(c)) << "TIME_WAIT expired: the connection must be gone";
}

TEST_F(Close, FinAndAckTogetherInFinWait1)
{
	end_send();
	expect_fin();
	peer_send(c, FIN | ACK); // acks our FIN and closes in one segment
	TcpSegment a = next_out("ACK of the peer's FIN");
	EXPECT_EQ(a.ack, c.peer_nxt);
	EXPECT_EQ(info(c).state, TH_TIME_WAIT);
}

TEST_F(Close, SimultaneousCloseGoesThroughClosing)
{
	end_send();
	TcpSegment fin = expect_fin();
	// peer's FIN crosses ours: it doesn't ack our FIN yet
	TcpSegment pf = seg_for(c, FIN | ACK);
	pf.ack = fin.seq; // acks everything before our FIN
	inject(pf);
	c.peer_nxt += 1;
	TcpSegment a = next_out("ACK of the peer's FIN");
	EXPECT_EQ(a.ack, c.peer_nxt);
	EXPECT_EQ(info(c).state, TH_CLOSING);
	peer_send(c, ACK); // now acks our FIN
	EXPECT_EQ(info(c).state, TH_TIME_WAIT);
}

TEST_F(Close, PassiveCloseDeliversEofThenLastAck)
{
	peer_send(c, ACK | PSH, pattern(300));
	peer_send(c, FIN | ACK);
	TcpSegment a = next_out("immediate ACK of the FIN");
	EXPECT_EQ(a.ack, c.peer_nxt);
	EXPECT_EQ(info(c).state, TH_CLOSE_WAIT);

	EXPECT_EQ(app_read(c, 300), pattern(300)) << "data before the FIN is delivered first";
	int fd = c.fd;
	auto eof = call_with_timeout<long>(
	    [this, fd] {
		    uint8_t b[8];
		    return th_recv(st, fd, b, sizeof b);
	    },
	    2000);
	ASSERT_TRUE(eof.has_value()) << "finding 10: receive() must return at EOF";
	EXPECT_EQ(*eof, 0) << "EOF is a 0-byte read";

	ASSERT_EQ(end_send(), 0);
	expect_fin();
	EXPECT_EQ(info(c).state, TH_LAST_ACK);
	peer_send(c, ACK);
	EXPECT_FALSE(exists(c)) << "LAST_ACK + ACK: connection closed and removed";
}

TEST_F(Close, BlockedReaderWakesAtEof)
{
	int fd = c.fd;
	Pending<long> reader([this, fd] {
		uint8_t b[8];
		return th_recv(st, fd, b, sizeof b);
	});
	EXPECT_FALSE(reader.wait(50).has_value());
	peer_send(c, FIN | ACK);
	auto r = reader.wait(2000);
	ASSERT_TRUE(r.has_value()) << "finding 14: a reader blocked before the FIN must wake up";
	EXPECT_EQ(*r, 0);
	drain_out();
}

TEST_F(Close, DataInFinWait2IsStillAcked)
{
	end_send();
	expect_fin();
	peer_send(c, ACK);
	ASSERT_EQ(info(c).state, TH_FIN_WAIT_2);
	peer_send(c, ACK | PSH, pattern(200));
	advance(500);
	TcpSegment a = next_out("ACK for data received in FIN_WAIT_2 (finding 8)");
	EXPECT_EQ(a.ack, c.peer_nxt);
	app_read(c, 200);
}

TEST_F(Close, FinIsRetransmittedUntilAcked)
{
	end_send();
	TcpSegment fin = expect_fin();
	advance(1100);
	TcpSegment again = next_out("retransmitted FIN");
	EXPECT_TRUE(again.flags & FIN);
	EXPECT_EQ(again.seq, fin.seq);
	peer_send(c, ACK);
	advance(5000);
	expect_nothing_out("FIN acked");
}

TEST_F(Close, FinAfterQueuedDataIsSentLast)
{
	auto d = pattern(5000);
	app_write(c, d);
	end_send();
	std::vector<uint8_t> got;
	bool fin_seen = false;
	uint32_t fin_seq = 0;
	for (int i = 0; i < 20 && !fin_seen; i++) {
		for (auto &s : drain_out()) {
			peer_saw(c, s);
			EXPECT_FALSE(fin_seen) << "data after the FIN: " << s.describe();
			got.insert(got.end(), s.payload.begin(), s.payload.end());
			if (s.flags & FIN) {
				fin_seen = true;
				fin_seq = s.seq + (uint32_t)s.payload.size();
			}
		}
		peer_send(c, ACK);
	}
	ASSERT_TRUE(fin_seen);
	EXPECT_EQ(got, d);
	EXPECT_EQ(fin_seq, c.stack_iss + 1 + 5000u);
	EXPECT_EQ(info(c).state, TH_FIN_WAIT_2);
}

TEST_F(Close, WriteAfterEndSendFails)
{
	end_send();
	expect_fin();
	int fd = c.fd;
	auto r = call_with_timeout<long>(
	    [this, fd] {
		    uint8_t b[4] = {1, 2, 3, 4};
		    return th_send_once(st, fd, b, 4);
	    },
	    2000);
	ASSERT_TRUE(r.has_value()) << "write after shutdown must not block";
	EXPECT_LT(*r, 0);
}

TEST_F(Close, EndSendTwiceSendsOneFin)
{
	end_send();
	end_send();
	auto segs = drain_out();
	int fins = 0;
	for (auto &s : segs)
		fins += (s.flags & FIN) ? 1 : 0;
	EXPECT_EQ(fins, 1);
}

TEST_F(Close, RetransmittedFinInTimeWaitIsAckedAgain)
{
	end_send();
	expect_fin();
	peer_send(c, ACK);
	peer_send(c, FIN | ACK);
	next_out("ACK of FIN");
	advance(30000, 100);
	// our ACK was lost: the peer retransmits its FIN
	TcpSegment again = seg_for(c, FIN | ACK);
	again.seq = c.peer_nxt - 1;
	inject(again);
	TcpSegment a = next_out("ACK of the retransmitted FIN");
	EXPECT_EQ(a.ack, c.peer_nxt);
	advance(45000, 100);
	EXPECT_TRUE(exists(c)) << "RFC 9293 3.10.7.4: a retransmitted FIN restarts the 2 MSL timer";
	advance(20000, 100);
	EXPECT_FALSE(exists(c));
}

// ------------------------------------------------------------------ resets

TEST_F(Close, ExactRstAbortsAndWakesBlockedReader)
{
	int fd = c.fd;
	Pending<long> reader([this, fd] {
		uint8_t b[8];
		return th_recv(st, fd, b, sizeof b);
	});
	EXPECT_FALSE(reader.wait(20).has_value());
	peer_send(c, RST); // seq == rcv_nxt exactly
	expect_nothing_out("never answer a valid RST");
	EXPECT_FALSE(exists(c)) << "a valid RST closes the connection";
	auto r = reader.wait(2000);
	ASSERT_TRUE(r.has_value()) << "a reader blocked on a reset connection must wake up";
	EXPECT_LT(*r, 0) << "a reset is an error, not EOF";
}

TEST_F(Close, InWindowRstGetsChallengeAck)
{
	TcpSegment r = seg_for(c, RST);
	r.seq = c.peer_nxt + 100; // in the window but not exact
	inject(r);
	TcpSegment a = next_out("challenge ACK (RFC 5961 3.2)");
	EXPECT_EQ(a.flags, ACK);
	EXPECT_EQ(a.ack, c.peer_nxt);
	EXPECT_EQ(info(c).state, TH_ESTABLISHED) << "the connection must survive";
}

TEST_F(Close, OutOfWindowRstIsIgnored)
{
	TcpSegment r = seg_for(c, RST);
	r.seq = c.peer_nxt - 100000;
	inject(r);
	expect_nothing_out("out-of-window RST is dropped silently");
	EXPECT_EQ(info(c).state, TH_ESTABLISHED);
}

TEST_F(Close, RstInTimeWaitRemovesTheConnection)
{
	end_send();
	expect_fin();
	peer_send(c, FIN | ACK);
	next_out("ACK");
	ASSERT_EQ(info(c).state, TH_TIME_WAIT);
	peer_send(c, RST);
	advance(100);
	EXPECT_FALSE(exists(c))
	    << "finding 37: a RST in TIME_WAIT must not pin the connection for 60 s";
}

// ------------------------------------------------------------------ listener

TEST_F(Close, ClosingListenerWakesBlockedAccept)
{
	Pending<int> acc([this] { return th_accept(st, l); });
	EXPECT_FALSE(acc.wait(20).has_value());
	guarded("close_socket on the listener", [this] { return th_close(st, l); });
	auto r = acc.wait(2000);
	ASSERT_TRUE(r.has_value()) << "accept() must return when its listener closes";
	EXPECT_LT(*r, 0);
}

TEST_F(Close, ClosingListenerAbortsQueuedConnections)
{
	// two connections complete the handshake but are never accepted
	PeerConn q[2];
	for (int i = 0; i < 2; i++) {
		q[i].stack_port = 9000;
		q[i].peer_port = (uint16_t)(42100 + i);
		q[i].peer_nxt = 10;
		inject(seg_for(q[i], SYN));
		q[i].peer_nxt++;
		TcpSegment sa = next_out("SYN-ACK");
		q[i].stack_nxt = sa.seq + 1;
		peer_send(q[i], ACK);
		ASSERT_EQ(info(q[i]).state, TH_ESTABLISHED);
	}
	guarded("close_socket on the listener", [this] { return th_close(st, l); });
	drain_out();
	for (auto &x : q)
		EXPECT_FALSE(exists(x)) << "queued connection left behind with no owner";
	EXPECT_EQ(info(c).state, TH_ESTABLISHED) << "already-accepted connections are not affected";
}

TEST_F(Close, SynToClosedListenerGetsRst)
{
	guarded("close_socket on the listener", [this] { return th_close(st, l); });
	PeerConn n;
	n.stack_port = 9000;
	n.peer_port = 42200;
	n.peer_nxt = 5;
	inject(seg_for(n, SYN));
	TcpSegment r = next_out("RST for a port nobody listens on");
	EXPECT_TRUE(r.flags & RST);
}
