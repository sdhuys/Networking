// Data transfer: receiving and reassembly, ACK and SACK generation, sending within the
// peer's window and cwnd, retransmission (RTO and fast retransmit), zero-window probing.

#include "stack_fixture.hpp"

#include <algorithm>
#include <map>
#include <random>

class Data : public StackTest
{
      protected:
	int l = -1;
	PeerConn c;

	void SetUp() override
	{
		StackTest::SetUp();
		l = listen(9000);
		c = open_passive(l, 9000, 41000);
	}

	// peer sends `data` starting at sequence offset `off` from its current peer_nxt,
	// without advancing peer_nxt
	int peer_send_at(uint32_t seq, const std::vector<uint8_t> &data, uint8_t flags = ACK | PSH)
	{
		TcpSegment s = seg_for(c, flags);
		s.seq = seq;
		s.payload = data;
		return inject(s);
	}

	// sends [from, to) of `d` (offsets from `base`) in segments of at most 1000 bytes
	void peer_send_range(uint32_t base, const std::vector<uint8_t> &d, size_t from, size_t to)
	{
		for (size_t at = from; at < to; at += 1000) {
			size_t end = std::min(to, at + 1000);
			peer_send_at(base + (uint32_t)at, slice(d, at, end));
		}
	}

	static std::vector<uint8_t> slice(const std::vector<uint8_t> &v, size_t from, size_t to)
	{
		return std::vector<uint8_t>(v.begin() + from, v.begin() + to);
	}

	// ACKs everything the stack has sent so far
	void ack_all()
	{
		peer_send(c, ACK);
	}

	// collects data segments until nothing more comes out; updates c.stack_nxt
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
};

// ------------------------------------------------------------------ receiving

TEST_F(Data, InOrderDataReachesTheApp)
{
	auto d = pattern(1000);
	peer_send(c, ACK | PSH, d);
	EXPECT_EQ(app_read(c, 1000), d);
	EXPECT_EQ(info(c).rcv_nxt, c.peer_nxt);
}

TEST_F(Data, SingleSegmentAckIsDelayedButSent)
{
	peer_send(c, ACK | PSH, pattern(100));
	expect_nothing_out("one small segment: the ACK may be delayed");
	advance(500);
	TcpSegment a = next_out("delayed ACK within 500 ms (RFC 9293 3.8.6.3)");
	EXPECT_EQ(a.flags & ACK, ACK);
	EXPECT_EQ(a.ack, c.peer_nxt);
	EXPECT_TRUE(a.payload.empty());
	app_read(c, 100);
}

// A data segment carries the ACK the delayed-ACK timer was waiting to send, so the timer
// must be cancelled: otherwise a redundant pure ACK follows, which the peer can count as a
// duplicate ACK.
TEST_F(Data, PiggybackedAckCancelsTheDelayedAck)
{
	peer_send(c, ACK | PSH, pattern(100));
	expect_nothing_out("one small segment: the ACK may be delayed");
	app_write(c, pattern(300, 2));
	auto out = take_data();
	ASSERT_EQ(out.size(), 1u);
	EXPECT_EQ(out[0].ack, c.peer_nxt) << "the data segment acknowledges the peer's data";
	advance(500);
	expect_nothing_out("no pure ACK after the data segment already acknowledged everything");
	app_read(c, 100);
	ack_all();
}

TEST_F(Data, AtLeastEverySecondFullSegmentIsAckedImmediately)
{
	uint32_t mss = info(c).rcv_mss;
	ASSERT_GT(mss, 0u);
	peer_send(c, ACK, pattern(mss, 1));
	peer_send(c, ACK, pattern(mss, 2));
	TcpSegment a = next_out("ACK for two full-sized segments (RFC 9293 3.8.6.3)");
	EXPECT_EQ(a.ack, c.peer_nxt);
	app_read(c, 2 * mss);
}

TEST_F(Data, OutOfOrderSegmentGetsImmediateDupAckWithSack)
{
	auto d = pattern(3000);
	uint32_t base = c.peer_nxt;
	peer_send_at(base + 1000, slice(d, 1000, 2000));
	TcpSegment a = next_out("immediate duplicate ACK for out-of-order data (RFC 5681 4.2)");
	EXPECT_EQ(a.ack, base) << "the ACK must still point at the hole";
	ASSERT_EQ(a.opts.sacks.size(), 1u) << "SACK was negotiated: report the block";
	EXPECT_EQ(a.opts.sacks[0], std::make_pair(base + 1000, base + 2000));

	peer_send_at(base, slice(d, 0, 1000));
	TcpSegment a2 = next_out("immediate ACK when the hole is filled");
	EXPECT_EQ(a2.ack, base + 2000);
	EXPECT_TRUE(a2.opts.sacks.empty()) << "no blocks left above rcv_nxt";

	peer_send_at(base + 2000, slice(d, 2000, 3000));
	c.peer_nxt = base + 3000;
	EXPECT_EQ(app_read(c, 3000), d);
	drain_out();
}

TEST_F(Data, SegmentSpanningAStoredBlockIsReassembled)
{
	// finding 1: [+100, +200) stored first, then [0, +300) arrives
	auto d = pattern(300);
	uint32_t base = c.peer_nxt;
	peer_send_at(base + 100, slice(d, 100, 200));
	peer_send_at(base, d);
	c.peer_nxt = base + 300;
	EXPECT_EQ(app_read(c, 300), d);
	EXPECT_EQ(info(c).rcv_nxt, base + 300);
	drain_out();
}

TEST_F(Data, ShuffledOverlappingDuplicatedSegmentsReassembleExactly)
{
	const size_t total = 60000;
	auto d = pattern(total, 7);
	uint32_t base = c.peer_nxt;

	std::mt19937 rng(1234);
	struct Piece {
		size_t from, to;
	};
	std::vector<Piece> pieces;
	for (size_t at = 0; at < total;) {
		size_t len = 1 + rng() % 1400;
		size_t to = std::min(total, at + len);
		pieces.push_back({at, to});
		// an overlapping piece reaching back into the previous data
		if (at > 0 && rng() % 3 == 0) {
			size_t back = std::min<size_t>(at, 1 + rng() % 700);
			pieces.push_back({at - back, std::min(total, at + rng() % 700)});
		}
		if (rng() % 5 == 0)
			pieces.push_back({at, to}); // exact duplicate
		at = to;
	}
	std::shuffle(pieces.begin() + 1, pieces.end(), rng); // keep the first in place

	for (auto &p : pieces) {
		if (p.to <= p.from)
			continue;
		peer_send_at(base + (uint32_t)p.from, slice(d, p.from, p.to));
		drain_out();
	}
	c.peer_nxt = base + total;
	EXPECT_EQ(app_read(c, total, 5000), d);
	EXPECT_EQ(info(c).rcv_nxt, base + (uint32_t)total);
	drain_out();
}

TEST_F(Data, FirstSackBlockIsTheMostRecentArrival)
{
	// RFC 2018 section 4: the first block must contain the segment that triggered the ACK
	uint32_t base = c.peer_nxt;
	auto d = pattern(10000);
	for (uint32_t off : {6000u, 2000u, 8000u, 4000u}) {
		peer_send_at(base + off, slice(d, off, off + 1000));
		TcpSegment a = next_out("dup ACK with SACK");
		ASSERT_FALSE(a.opts.sacks.empty());
		EXPECT_EQ(a.opts.sacks[0].first, base + off)
		    << "first block is not the newest arrival: " << a.describe();
	}
	// fill the holes so the app read matches
	peer_send_range(base, d, 0, 10000);
	c.peer_nxt = base + 10000;
	app_read(c, 10000);
	drain_out();
}

TEST_F(Data, SackOptionsFitBesideTimestamps)
{
	// finding 4: with timestamps, only 3 SACK blocks fit in 40 option bytes
	ASSERT_TRUE(c.ts);
	uint32_t base = c.peer_nxt;
	auto d = pattern(12000);
	TcpSegment last;
	for (uint32_t off = 1000; off < 11000; off += 2000) {
		peer_send_at(base + off, slice(d, off, off + 1000));
		last = next_out("dup ACK with SACK");
		EXPECT_LE(last.options_len, 40u);
		EXPECT_LE(last.opts.sacks.size(), 3u) << last.describe();
		EXPECT_TRUE(last.opts.ts.has_value()) << "timestamps must stay on every segment";
	}
	EXPECT_EQ(last.opts.sacks.size(), 3u) << "five holes: report as many blocks as fit";
	peer_send_range(base, d, 0, 12000);
	c.peer_nxt = base + 12000;
	app_read(c, 12000);
	drain_out();
}

TEST_F(Data, DuplicateOldSegmentIsAckedNotDelivered)
{
	auto d = pattern(500);
	peer_send(c, ACK | PSH, d);
	app_read(c, 500);
	drain_out();
	peer_send_at(c.peer_nxt - 500, d); // retransmission of data we already have
	TcpSegment a = next_out("ACK for a duplicate segment (RFC 9293 3.10.7.4)");
	EXPECT_EQ(a.ack, c.peer_nxt);
	EXPECT_EQ(info(c).rcv_contiguous_bytes, 0u) << "duplicate data must not be delivered twice";
}

TEST_F(Data, SegmentWithBadChecksumIsDropped)
{
	TcpSegment s = seg_for(c, ACK | PSH);
	s.payload = pattern(200);
	auto f = build(s);
	f.back() ^= 0xFF; // corrupt the payload, checksum now wrong
	guarded("processing a corrupted segment",
		[this, f] { return th_inject(st, f.data(), f.size()); });
	expect_nothing_out("a corrupted segment is dropped silently");
	EXPECT_EQ(info(c).rcv_nxt, c.peer_nxt);
	advance(500);
	expect_nothing_out("not even a delayed ACK");
}

TEST_F(Data, AppReadOpensWindowAndAnnouncesIt)
{
	// fill the receive buffer (512 KB) without reading
	uint32_t mss = info(c).rcv_mss;
	size_t sent = 0;
	for (int i = 0; i < 2000; i++) {
		th_conn_info ci = info(c);
		uint32_t wnd = (uint32_t)ci.rcv_wnd << c.stack_wscale;
		if (wnd < mss)
			break;
		peer_send(c, ACK, pattern(mss, i));
		sent += mss;
		for (auto &s : drain_out())
			peer_saw(c, s);
	}
	advance(300);
	auto acks = drain_out();
	ASSERT_GT(sent, 400000u) << "receive buffer should take hundreds of KB";
	uint32_t last_window = 0xFFFFFFFF;
	for (auto &a : acks)
		last_window = a.window;
	(void)last_window;

	app_read(c, sent, 10000);
	auto upd = drain_out();
	ASSERT_FALSE(upd.empty()) << "after the app drains a full buffer, announce the open window";
	EXPECT_GT((uint32_t)upd.back().window << c.stack_wscale, mss);
}

// ------------------------------------------------------------------ sending

TEST_F(Data, AppDataIsSegmentedByMssInOrder)
{
	auto d = pattern(10000);
	app_write(c, d);
	auto segs = take_data();
	ASSERT_FALSE(segs.empty());
	uint32_t mss = info(c).snd_mss;
	std::vector<uint8_t> got;
	uint32_t expect_seq = c.stack_iss + 1;
	for (auto &s : segs) {
		EXPECT_EQ(s.seq, expect_seq) << "segments must be contiguous: " << s.describe();
		EXPECT_LE(s.payload.size(), mss) << s.describe();
		EXPECT_TRUE(s.flags & ACK);
		EXPECT_EQ(s.ack, c.peer_nxt);
		expect_seq += (uint32_t)s.payload.size();
		got.insert(got.end(), s.payload.begin(), s.payload.end());
	}
	EXPECT_EQ(got, d);
}

TEST_F(Data, InitialWindowIsAtMostTenSegments)
{
	app_write(c, pattern(100000));
	auto segs = take_data();
	size_t bytes = 0;
	for (auto &s : segs)
		bytes += s.payload.size();
	EXPECT_LE(bytes, 10u * info(c).snd_mss) << "RFC 6928: initial cwnd at most 10 segments";
	EXPECT_GT(bytes, 0u);
}

TEST_F(Data, AcksReleaseMoreData)
{
	auto d = pattern(100000);
	app_write(c, d);
	std::vector<uint8_t> got;
	for (int round = 0; round < 100 && got.size() < d.size(); round++) {
		auto segs = take_data();
		for (auto &s : segs)
			got.insert(got.end(), s.payload.begin(), s.payload.end());
		ack_all();
	}
	EXPECT_EQ(got.size(), d.size());
	EXPECT_EQ(got, d);
	EXPECT_EQ(info(c).snd_used_bytes, 0u);
}

TEST_F(Data, SenderRespectsPeerWindowWithoutScaling)
{
	// a peer without window scaling: the window field is in bytes
	PeerConn p = open_passive(l, 9000, 41001, [] {
		TcpOptions o;
		o.mss = 1460;
		return o;
	}());
	p.peer_window = 3000;
	peer_send(p, ACK); // window update to 3000
	drain_out();

	int fd = p.fd;
	auto d = pattern(20000);
	Pending<long> w([this, fd, d] { return th_send(st, fd, d.data(), d.size()); });
	for (int i = 0; i < 1000 && info(p).snd_used_bytes == 0; i++)
		std::this_thread::sleep_for(
		    std::chrono::milliseconds(1)); // let the app thread write
	size_t outstanding = 0;
	for (auto &s : drain_out()) {
		peer_saw(p, s);
		outstanding += s.payload.size();
	}
	EXPECT_LE(outstanding, 3000u) << "never send beyond the peer's window";
	EXPECT_GT(outstanding, 0u);
	p.peer_window = 65535;
	peer_send(p, ACK);
	for (int i = 0; i < 50; i++) {
		for (auto &s : drain_out())
			peer_saw(p, s);
		peer_send(p, ACK);
	}
	EXPECT_TRUE(w.wait(2000).has_value());
}

TEST_F(Data, RtoRetransmitsOldestUnackedSegmentAndBacksOff)
{
	app_write(c, pattern(1000));
	auto first = take_data();
	ASSERT_EQ(first.size(), 1u);
	advance(1000);
	TcpSegment r = next_out("retransmission after the 1 s RTO");
	EXPECT_EQ(r.seq, first[0].seq);
	EXPECT_EQ(r.payload, first[0].payload);
	EXPECT_EQ(info(c).rto_ms, 2000u) << "RFC 6298 5.5: back off the timer";
	advance(1990);
	expect_nothing_out("second timeout is at 2 s");
	advance(20);
	TcpSegment r2 = next_out("second retransmission");
	EXPECT_EQ(r2.seq, first[0].seq);
	ack_all();
	advance(10000);
	expect_nothing_out("everything acked: no more retransmissions");
}

TEST_F(Data, AckOfEverythingStopsTheRto)
{
	app_write(c, pattern(1000));
	take_data();
	ack_all();
	advance(5000);
	expect_nothing_out("nothing outstanding");
	EXPECT_FALSE(info(c).retransmit) << "finding 6: retransmit flag left set";
	app_write(c, pattern(500, 9));
	auto more = take_data();
	ASSERT_EQ(more.size(), 1u) << "the connection must still send new data";
}

TEST_F(Data, ThreeDupAcksTriggerFastRetransmit)
{
	app_write(c, pattern(10 * 1400));
	auto segs = take_data();
	ASSERT_GE(segs.size(), 5u);
	uint32_t lost = segs[1].seq; // segment 2 is "lost"
	// ACK segment 1, then three duplicate ACKs as segments 3..5 arrive
	TcpSegment a = seg_for(c, ACK);
	a.ack = segs[1].seq;
	inject(a);
	for (size_t i = 0; i < 3; i++) {
		// segment 3+i arrived: SACK everything from segment 3 to its end
		const TcpSegment &arrived = segs[2 + i];
		TcpSegment dup = seg_for(c, ACK);
		dup.ack = segs[1].seq;
		dup.opts.sacks = {{segs[2].seq, arrived.seq + (uint32_t)arrived.payload.size()}};
		inject(dup);
	}
	TcpSegment r = next_out("fast retransmission after three duplicate ACKs (RFC 5681 3.2)");
	EXPECT_EQ(r.seq, lost);
	EXPECT_EQ(r.payload, segs[1].payload);
	drain_out();
}

TEST_F(Data, IdleWindowUpdatesAreNotDuplicateAcks)
{
	// finding 6(b): pure ACKs with nothing outstanding must not start fast recovery
	app_write(c, pattern(1000));
	take_data();
	ack_all();
	for (uint16_t w : {60000, 50000, 40000, 65535}) {
		c.peer_window = w;
		peer_send(c, ACK);
	}
	expect_nothing_out("window updates while idle");
	EXPECT_FALSE(info(c).retransmit);
	app_write(c, pattern(700, 3));
	auto more = take_data();
	ASSERT_EQ(more.size(), 1u);
	EXPECT_EQ(more[0].payload.size(), 700u);
}

TEST_F(Data, ZeroWindowIsProbedWithBackoffAndRecovers)
{
	c.peer_window = 0;
	peer_send(c, ACK);
	app_write(c, pattern(3000));
	auto now = take_data();
	EXPECT_TRUE(now.empty()) << "window is zero: no data";

	std::vector<uint64_t> probe_times;
	uint64_t t0 = fake_clock_ms();
	for (int ms = 0; ms < 20000 && probe_times.size() < 3; ms += 10) {
		advance(10);
		for (auto &s : drain_out()) {
			probe_times.push_back(fake_clock_ms() - t0);
			EXPECT_LE(s.payload.size(), 1u)
			    << "a probe carries at most one byte: " << s.describe();
			peer_send(c, ACK); // still zero window
		}
	}
	ASSERT_EQ(probe_times.size(), 3u)
	    << "finding 7: probes must keep coming while the window is zero";
	EXPECT_LT(probe_times[1] - probe_times[0], probe_times[2] - probe_times[1] + 50)
	    << "probe interval backs off";

	c.peer_window = 65535;
	peer_send(c, ACK);
	std::vector<uint8_t> got;
	for (int i = 0; i < 20 && got.size() < 3000; i++) {
		for (auto &s : take_data())
			got.insert(got.end(), s.payload.begin(), s.payload.end());
		ack_all();
		advance(10);
	}
	EXPECT_GE(got.size(), 3000u) << "data must flow once the window opens";
}

TEST_F(Data, UnansweredRetransmissionsAbortTheConnection)
{
	int fd = c.fd;
	Pending<long> reader([this, fd] {
		uint8_t b[16];
		return th_recv(st, fd, b, sizeof b);
	});
	app_write(c, pattern(1000));
	take_data();
	for (int i = 0; i < 1200 && exists(c); i++)
		advance(1000, 100);
	EXPECT_FALSE(exists(c)) << "finding 13: give up after TCP_DATA_TIMEOUTS_MAX timeouts";
	auto r = reader.wait(2000);
	ASSERT_TRUE(r.has_value()) << "a reader blocked on an aborted connection must wake up";
	EXPECT_LT(*r, 0);
	drain_out();
}

TEST_F(Data, AckForDataNeverSentGetsAChallengeAck)
{
	TcpSegment s = seg_for(c, ACK);
	s.ack = c.stack_nxt + 100000;
	inject(s);
	TcpSegment a = next_out("ACK in reply to an ACK of unsent data (RFC 9293 3.10.7.4)");
	EXPECT_EQ(a.ack, c.peer_nxt);
	EXPECT_EQ(info(c).state, TH_ESTABLISHED);
}

// Found by the Linux interop run (echo server, 20 MB transfer): the stack's receive window
// was 0, Linux kept probing it, and Linux's ACKs for the stack's data were ignored, so both
// sides waited forever. After a probe, Linux's ACKs carry seq = rcv_nxt + probe length,
// which fails the acceptability test while our window is 0. RFC 9293 3.10.7.4: "If the
// RCV.WND is zero, no segments will be acceptable, but special allowance should be made to
// accept valid ACKs".
class ZeroReceiveWindow : public Data
{
      protected:
	// Sends data without the app reading until the advertised window is exactly 0.
	// The segments acknowledge only up to `ack`, so the stack's own data stays unacked.
	void close_receive_window(uint32_t ack)
	{
		uint32_t mss = info(c).rcv_mss;
		for (int i = 0; i < 3000; i++) {
			uint32_t wnd = (uint32_t)info(c).rcv_wnd << c.stack_wscale;
			if (wnd == 0)
				break;
			TcpSegment d = seg_for(c, ACK);
			d.ack = ack;
			d.payload = pattern(std::min(wnd, mss), i);
			inject(d);
			c.peer_nxt += (uint32_t)d.payload.size();
			drain_out();
		}
		advance(300);
		drain_out();
	}
};

TEST_F(ZeroReceiveWindow, AckAfterAProbeStillAdvancesSndUna)
{
	uint32_t old_ack = c.stack_nxt;
	app_write(c, pattern(5000, 77));
	ASSERT_FALSE(take_data().empty());
	uint32_t acked_up_to = c.stack_nxt;

	close_receive_window(old_ack);
	ASSERT_EQ(info(c).snd_una, old_ack) << "nothing of our data acked yet";
	ASSERT_EQ(info(c).rcv_wnd, 0u) << "receive window should be closed";

	// Linux probes the closed window with 8 bytes (not acceptable, must be answered)
	TcpSegment probe = seg_for(c, ACK);
	probe.payload = pattern(8, 1);
	probe.ack = old_ack; // acks nothing new yet
	inject(probe);
	TcpSegment reply = next_out("ACK in reply to the zero-window probe");
	EXPECT_EQ(reply.ack, c.peer_nxt) << "the probe's data must not be accepted";

	// Linux now acks our data from seq = rcv_nxt + 8
	TcpSegment a = seg_for(c, ACK);
	a.seq = c.peer_nxt + 8;
	a.ack = acked_up_to;
	th_conn_info before = info(c);
	int r = inject(a);
	EXPECT_EQ(info(c).snd_una, acked_up_to)
	    << "a valid ACK was ignored because our window is 0 (result " << r << ", rcv_wnd "
	    << before.rcv_wnd << ", snd_una before " << before.snd_una << ")";
	drain_out();
}

TEST_F(ZeroReceiveWindow, AckFieldOfAZeroWindowProbeIsUsed)
{
	uint32_t old_ack = c.stack_nxt;
	app_write(c, pattern(5000, 78));
	ASSERT_FALSE(take_data().empty());
	uint32_t acked_up_to = c.stack_nxt;

	close_receive_window(old_ack);
	ASSERT_EQ(info(c).rcv_wnd, 0u);

	TcpSegment probe = seg_for(c, ACK); // data we can't take, but a valid new ACK
	probe.payload = pattern(8, 2);
	probe.ack = acked_up_to;
	inject(probe);
	EXPECT_EQ(info(c).snd_una, acked_up_to)
	    << "the probe's data is unacceptable, its ACK is not";
	TcpSegment reply = next_out("ACK in reply to the probe");
	EXPECT_EQ(reply.ack, c.peer_nxt) << "the probe's data must not be accepted";
	drain_out();
}
