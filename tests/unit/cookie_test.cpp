// SYN cookies: switching to cookie mode at the half-open limit, completing a connection
// from a cookie, and data on the completing ACK.

#include "stack_fixture.hpp"

class Cookies : public StackTest
{
      protected:
	int l = -1;
	static constexpr int HALF_OPEN_LIMIT = 256; // TCP_LSTNR_HALF_OPENS_LIMIT

	void SetUp() override
	{
		StackTest::SetUp();
		l = listen(9000);
	}

	// fills the listener with half-open connections (SYN, no final ACK)
	void fill_half_open()
	{
		for (int i = 0; i < HALF_OPEN_LIMIT; i++) {
			PeerConn h;
			h.stack_port = 9000;
			h.peer_port = (uint16_t)(10000 + i);
			h.peer_nxt = 1;
			TcpSegment syn = seg_for(h, SYN);
			syn.opts = linux_syn_options();
			inject(syn);
			next_out("SYN-ACK");
		}
	}

	// sends a SYN that should get a cookie SYN-ACK; returns the connection state
	PeerConn cookie_syn(uint16_t port, TcpSegment *synack_out)
	{
		PeerConn c;
		c.stack_port = 9000;
		c.peer_port = port;
		c.peer_iss = c.peer_nxt = 900000;
		TcpSegment syn = seg_for(c, SYN);
		syn.opts = linux_syn_options();
		inject(syn);
		c.peer_nxt++;
		TcpSegment sa = next_out("cookie SYN-ACK");
		*synack_out = sa;
		c.stack_iss = sa.seq;
		c.stack_nxt = sa.seq + 1;
		return c;
	}
};

TEST_F(Cookies, AtHalfOpenLimitSynAckCarriesACookie)
{
	fill_half_open();
	TcpSegment sa;
	PeerConn c = cookie_syn(30000, &sa);
	EXPECT_EQ(sa.flags, SYN | ACK);
	EXPECT_EQ(sa.ack, c.peer_iss + 1);
	ASSERT_TRUE(sa.opts.mss.has_value()) << "the MSS is encoded in the cookie and announced";
	EXPECT_FALSE(sa.opts.ts.has_value()) << "timestamps can't be kept without state";
	EXPECT_FALSE(sa.opts.wscale.has_value()) << "window scaling can't be kept without state";
	EXPECT_FALSE(exists(c)) << "cookie mode keeps no state for the SYN";
}

TEST_F(Cookies, CookieAckCreatesAWorkingConnection)
{
	fill_half_open();
	TcpSegment sa;
	PeerConn c = cookie_syn(30001, &sa);
	c.ts = false;
	peer_send(c, ACK);
	th_conn_info i = info(c);
	ASSERT_EQ(i.state, TH_ESTABLISHED) << "a valid cookie ACK must create the connection";
	EXPECT_EQ(i.rcv_nxt, c.peer_nxt) << "finding 11: rcv_nxt one too low";
	EXPECT_GT(i.snd_wnd, 0u) << "finding 11: peer window left at 0";
	EXPECT_GT(i.rcv_wnd, 0u) << "finding 11: our window left at 0";

	auto fd = call_with_timeout<int>([this] { return th_accept(st, l); }, 2000);
	ASSERT_TRUE(fd.has_value());
	c.fd = *fd;

	// data both ways
	peer_send(c, ACK | PSH, pattern(1000));
	EXPECT_EQ(app_read(c, 1000), pattern(1000));
	app_write(c, pattern(2000, 5));
	std::vector<uint8_t> got;
	for (auto &s : drain_out()) {
		EXPECT_EQ(s.dst_port, c.peer_port)
		    << "finding 11: peer port stored in the wrong byte order";
		got.insert(got.end(), s.payload.begin(), s.payload.end());
	}
	EXPECT_EQ(got, pattern(2000, 5));
}

TEST_F(Cookies, DataOnTheCookieAckIsDelivered)
{
	fill_half_open();
	TcpSegment sa;
	PeerConn c = cookie_syn(30002, &sa);
	peer_send(c, ACK | PSH, pattern(500, 3));
	ASSERT_EQ(info(c).state, TH_ESTABLISHED);
	auto fd = call_with_timeout<int>([this] { return th_accept(st, l); }, 2000);
	ASSERT_TRUE(fd.has_value());
	c.fd = *fd;
	EXPECT_EQ(app_read(c, 500), pattern(500, 3))
	    << "finding 11: data on the completing ACK was dropped";
	drain_out();
}

TEST_F(Cookies, AckWithWrongCookieCreatesNothing)
{
	fill_half_open();
	TcpSegment sa;
	PeerConn c = cookie_syn(30003, &sa);
	c.stack_nxt += 12345; // not the cookie
	peer_send(c, ACK);
	EXPECT_FALSE(exists(c));
	drain_out();
}
