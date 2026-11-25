// The stack's building blocks on their own, without a stack around them: the timer heap,
// the intrusive queue, the packet pool and packet ring buffer, the socket fd table, the
// checksum functions and the routing table.

#include "fake_env.h"
#include "harness.h"

#include "checksum.h"
#include "nw_interface.h"
#include "queue.h"
#include "routing_table.h"
#include "sockfd_manager.h"
extern "C" {
#include "heap.h" // has no extern "C" of its own
}

#include <gtest/gtest.h>

#include <algorithm>
#include <arpa/inet.h>
#include <cstring>
#include <random>
#include <set>
#include <thread>
#include <vector>

// ------------------------------------------------------------------ heap

class Heap : public ::testing::Test
{
      protected:
	struct min_heap *h = nullptr;
	std::vector<heap_node> nodes = std::vector<heap_node>(1000);
	void SetUp() override
	{
		h = heap_create(1024);
		ASSERT_NE(h, nullptr);
		for (auto &n : nodes)
			n.index = NODE_NOT_IN_HEAP;
	}
	void TearDown() override
	{
		heap_destroy(h);
	}
	std::vector<uint64_t> pop_all()
	{
		std::vector<uint64_t> v;
		while (heap_node *n = heap_pop(h)) {
			EXPECT_EQ(n->index, NODE_NOT_IN_HEAP) << "a popped node must be marked out";
			v.push_back(n->priority);
		}
		return v;
	}
};

TEST_F(Heap, EmptyHeapPopsAndPeeksNothing)
{
	EXPECT_EQ(heap_pop(h), nullptr);
	EXPECT_EQ(heap_peek(h), nullptr);
}

TEST_F(Heap, PopsInPriorityOrder)
{
	std::mt19937 rng(1);
	std::vector<uint64_t> prios;
	for (auto &n : nodes) {
		uint64_t p = rng() % 5000; // duplicates included
		ASSERT_TRUE(heap_push(h, &n, p));
		prios.push_back(p);
	}
	std::sort(prios.begin(), prios.end());
	EXPECT_EQ(heap_peek(h)->priority, prios.front());
	EXPECT_EQ(pop_all(), prios);
}

TEST_F(Heap, RemoveAnyNodeKeepsTheOrder)
{
	std::mt19937 rng(2);
	std::vector<uint64_t> kept;
	for (size_t i = 0; i < 300; i++)
		heap_push(h, &nodes[i], rng() % 1000);
	for (size_t i = 0; i < 300; i++) {
		if (i % 3 == 0) {
			EXPECT_TRUE(heap_remove(h, &nodes[i]));
			EXPECT_EQ(nodes[i].index, NODE_NOT_IN_HEAP);
		} else {
			kept.push_back(nodes[i].priority);
		}
	}
	EXPECT_FALSE(heap_remove(h, &nodes[0])) << "removing a node twice must fail";
	EXPECT_FALSE(heap_remove(h, &nodes[500])) << "a node that was never pushed";
	std::sort(kept.begin(), kept.end());
	EXPECT_EQ(pop_all(), kept);
}

TEST_F(Heap, UpdateMovesANodeBothWays)
{
	for (size_t i = 0; i < 100; i++)
		heap_push(h, &nodes[i], 100 + i);
	heap_update(h, &nodes[50], 1); // to the front
	EXPECT_EQ(heap_peek(h), &nodes[50]);
	heap_update(h, &nodes[50], 10000); // to the back
	heap_update(h, &nodes[0], 5000);
	auto order = pop_all();
	EXPECT_TRUE(std::is_sorted(order.begin(), order.end()));
	EXPECT_EQ(order.back(), 10000u);
	EXPECT_EQ(order[order.size() - 2], 5000u);
}

TEST_F(Heap, PushBeyondCapacityFails)
{
	struct min_heap *small = heap_create(4);
	heap_node n[5];
	for (auto &x : n)
		x.index = NODE_NOT_IN_HEAP;
	for (int i = 0; i < 4; i++)
		EXPECT_TRUE(heap_push(small, &n[i], i));
	EXPECT_FALSE(heap_push(small, &n[4], 9));
	EXPECT_EQ(n[4].index, NODE_NOT_IN_HEAP) << "a refused node must stay marked out";
	heap_destroy(small);
}

// ------------------------------------------------------------------ queue

namespace
{
struct Item {
	queue_node node{Q_NODE_UNLINKED};
	int value = 0;
	int refs = 0;
};
Item *item_of(queue_node *n)
{
	return reinterpret_cast<Item *>(reinterpret_cast<char *>(n) - offsetof(Item, node));
}
void item_retain(queue_node *n)
{
	item_of(n)->refs++;
}
void item_release(queue_node *n)
{
	item_of(n)->refs--;
}
} // namespace

TEST(Queue, IsFifoAndCountsReferences)
{
	struct queue *q = create_q(item_release, item_retain, 0);
	Item items[5];
	for (int i = 0; i < 5; i++) {
		items[i].value = i;
		ASSERT_TRUE(push_q(q, &items[i].node));
		EXPECT_EQ(items[i].refs, 1) << "push takes the queue's reference";
	}
	for (int i = 0; i < 5; i++) {
		queue_node *n = pop_q(q);
		ASSERT_NE(n, nullptr);
		EXPECT_EQ(item_of(n)->value, i);
		EXPECT_EQ(n->nxt, Q_NODE_UNLINKED) << "popped nodes are marked unlinked";
		EXPECT_EQ(item_of(n)->refs, 1) << "pop hands the reference to the caller";
	}
	EXPECT_EQ(pop_q(q), nullptr);
	destroy_q(q);
}

TEST(Queue, BoundedQueueRefusesWhenFull)
{
	struct queue *q = create_q(item_release, item_retain, 2);
	Item a, b, c;
	EXPECT_TRUE(push_q(q, &a.node));
	EXPECT_FALSE(q_full(q));
	EXPECT_TRUE(push_q(q, &b.node));
	EXPECT_TRUE(q_full(q));
	EXPECT_FALSE(push_q(q, &c.node));
	EXPECT_EQ(c.refs, 0) << "a refused push takes no reference";
	EXPECT_EQ(c.node.nxt, Q_NODE_UNLINKED);
	pop_q(q);
	EXPECT_TRUE(push_q(q, &c.node)) << "room again after a pop";
	destroy_q(q);
	EXPECT_EQ(b.refs, 0) << "destroy releases what is still queued";
	EXPECT_EQ(c.refs, 0);
}

TEST(Queue, CloseWakesABlockedPopAndRefusesPushes)
{
	struct queue *q = create_q(nullptr, nullptr, 0);
	queue_node *got = reinterpret_cast<queue_node *>(0x1234);
	std::thread t([&] { got = pop_q_blocking(q); });
	std::this_thread::sleep_for(std::chrono::milliseconds(50));
	close_q(q);
	t.join();
	EXPECT_EQ(got, nullptr) << "a closed queue returns NULL to blocked readers";
	Item a;
	EXPECT_FALSE(push_q(q, &a.node));
	destroy_q(q);
}

TEST(Queue, CloseDetachesTheQueuedNodes)
{
	struct queue *q = create_q(item_release, item_retain, 0);
	Item a, b;
	push_q(q, &a.node);
	push_q(q, &b.node);
	queue_node *list = close_q(q);
	ASSERT_EQ(list, &a.node);
	EXPECT_EQ(list->nxt, &b.node) << "the caller gets the old list to dispose of";
	EXPECT_EQ(pop_q(q), nullptr);
	destroy_q(q);
	EXPECT_EQ(a.refs, 1) << "detached nodes are the caller's, destroy doesn't touch them";
}

// ------------------------------------------------------------------ packet pool and ring

TEST(PacketPool, RetainAndReleaseCountReferences)
{
	int before = th_pool_free_count();
	void *p = th_pkt_alloc();
	ASSERT_NE(p, nullptr);
	EXPECT_EQ(th_pkt_refcount(p), 1u);
	EXPECT_EQ(th_pool_free_count(), before - 1);
	th_pkt_retain(p);
	th_pkt_release(p);
	EXPECT_EQ(th_pool_free_count(), before - 1) << "still referenced: not back in the pool";
	th_pkt_release(p);
	EXPECT_EQ(th_pool_free_count(), before) << "last release returns it";
}

TEST(PacketPool, EmptyPoolReturnsNull)
{
	th_global_init();
	std::vector<void *> taken;
	while (void *p = th_pkt_alloc())
		taken.push_back(p);
	EXPECT_GT(taken.size(), 0u);
	EXPECT_EQ(th_pkt_alloc(), nullptr);
	std::set<void *> distinct(taken.begin(), taken.end());
	EXPECT_EQ(distinct.size(), taken.size()) << "the pool handed out a packet twice";
	for (void *p : taken)
		th_pkt_release(p);
	EXPECT_EQ((size_t)th_pool_free_count(), taken.size());
}

TEST(PacketRing, IsFifoAndHoldsOneLessThanItsSize)
{
	EXPECT_EQ(th_ring_create(6), nullptr) << "sizes must be powers of two";
	void *r = th_ring_create(4);
	ASSERT_NE(r, nullptr);
	void *p[4];
	for (auto &x : p)
		x = th_pkt_alloc();
	EXPECT_TRUE(th_ring_write(r, p[0]));
	EXPECT_TRUE(th_ring_write(r, p[1]));
	EXPECT_TRUE(th_ring_write(r, p[2]));
	EXPECT_FALSE(th_ring_write(r, p[3])) << "one slot stays empty to tell full from empty";
	EXPECT_EQ(th_ring_read(r), p[0]);
	EXPECT_TRUE(th_ring_write(r, p[3])) << "wraps around";
	EXPECT_EQ(th_ring_read(r), p[1]);
	EXPECT_EQ(th_ring_read(r), p[2]);
	EXPECT_EQ(th_ring_read(r), p[3]);
	EXPECT_EQ(th_ring_read(r), nullptr);
	for (auto &x : p) {
		EXPECT_EQ(th_pkt_refcount(x), 1u)
		    << "the ring stores pointers, it takes no reference";
		th_pkt_release(x);
	}
	th_ring_destroy(r);
}

// ------------------------------------------------------------------ socket fds

namespace
{
// sockfd_manager has no destroy function: free what sockfd_manager_init allocated
void free_sockfd_manager(struct sockfd_manager *m)
{
	free(m->fd_sockets);
	free(m->free_stack);
	pthread_mutex_destroy(&m->fds_lock);
}
} // namespace

TEST(SockFds, AreUniqueAndReusedAfterFree)
{
	struct sockfd_manager m;
	ASSERT_EQ(sockfd_manager_init(&m), 0);
	std::set<int> fds;
	for (int i = 0; i < 100; i++) {
		int fd = get_sockfd(&m);
		ASSERT_GE(fd, 0);
		ASSERT_LT(fd, MAX_SOCKETS);
		EXPECT_TRUE(fds.insert(fd).second) << "fd " << fd << " handed out twice";
	}
	int some = *fds.begin();
	sockfd_free(&m, some);
	EXPECT_EQ(get_sockfd(&m), some) << "a freed fd is reused";
	free_sockfd_manager(&m);
}

TEST(SockFds, RunOutAfterMaxSockets)
{
	struct sockfd_manager m;
	ASSERT_EQ(sockfd_manager_init(&m), 0);
	for (int i = 0; i < MAX_SOCKETS; i++)
		ASSERT_GE(get_sockfd(&m), 0) << "at " << i;
	EXPECT_EQ(get_sockfd(&m), -1);
	sockfd_free(&m, 42);
	EXPECT_EQ(get_sockfd(&m), 42);
	free_sockfd_manager(&m);
}

// ------------------------------------------------------------------ checksums

namespace
{
uint16_t reference_checksum(const std::vector<uint8_t> &d)
{
	uint32_t s = 0;
	for (size_t i = 0; i + 1 < d.size(); i += 2)
		s += (uint32_t)((d[i] << 8) | d[i + 1]);
	if (d.size() & 1)
		s += (uint32_t)(d.back() << 8);
	while (s >> 16)
		s = (s & 0xFFFF) + (s >> 16);
	return (uint16_t)~s;
}
} // namespace

TEST(Checksum, Rfc1071Example)
{
	// RFC 1071 section 3: 00 01 f2 03 f4 f5 f6 f7 sums to 0xddf2
	std::vector<uint8_t> d = {0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7};
	checksum_chunk c = {d.data(), d.size()};
	EXPECT_EQ(calc_checksum(&c, 1), (uint16_t)~0xddf2);
}

TEST(Checksum, ChunkBoundariesDontMatter)
{
	std::mt19937 rng(3);
	for (int round = 0; round < 200; round++) {
		std::vector<uint8_t> d(1 + rng() % 300);
		for (auto &b : d)
			b = (uint8_t)rng();
		// split into up to 5 chunks at random (often odd) boundaries
		std::vector<size_t> cuts = {0, d.size()};
		for (int i = 0; i < 4; i++)
			cuts.push_back(rng() % (d.size() + 1));
		std::sort(cuts.begin(), cuts.end());
		std::vector<checksum_chunk> chunks;
		for (size_t i = 0; i + 1 < cuts.size(); i++)
			chunks.push_back({d.data() + cuts[i], cuts[i + 1] - cuts[i]});
		ASSERT_EQ(calc_checksum(chunks.data(), chunks.size()), reference_checksum(d))
		    << "round " << round << ", " << d.size() << " bytes";
	}
}

TEST(Checksum, Ipv4HeaderChecksumMatchesAKnownHeader)
{
	// a standard example header: 4500 0073 0000 4000 4011 [b861] c0a8 0001 c0a8 00c7
	alignas(4) uint8_t h[20] = {0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11,
				    0x00, 0x00, 0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7};
	uint16_t c = calc_ipv4_checksum(reinterpret_cast<ipv4_header *>(h), 5);
	std::memcpy(&h[10], &c, 2); // the stack stores the result as-is
	EXPECT_EQ(h[10], 0xb8);
	EXPECT_EQ(h[11], 0x61);
	EXPECT_EQ(calc_ipv4_checksum(reinterpret_cast<ipv4_header *>(h), 5), 0)
	    << "a header with a correct checksum sums to zero";
}

// ------------------------------------------------------------------ routing table

class Routes : public ::testing::Test
{
      protected:
	nw_interface ifs[3] = {};
	routing_table *t = nullptr;

	void TearDown() override
	{
		if (t) { // routing_table has no destroy function
			free(t->routes);
			free(t);
		}
	}

	static void ip(const char *s, uint8_t out[4])
	{
		in_addr a;
		inet_pton(AF_INET, s, &a);
		std::memcpy(out, &a.s_addr, 4);
	}
	static uint32_t u32(const char *s)
	{
		in_addr a;
		inet_pton(AF_INET, s, &a);
		return a.s_addr;
	}
	void SetUp() override
	{
		const uint8_t mac[6] = {2, 0, 0, 0, 0, 1};
		uint8_t a[4], m[4];
		ip("10.0.0.2", a);
		ip("255.255.255.0", m);
		set_nw_if_struct(&ifs[0], -1, "eth0", mac, a, m, 1500, nullptr, 0);
		ip("192.168.1.5", a);
		ip("255.255.0.0", m);
		set_nw_if_struct(&ifs[1], -1, "eth1", mac, a, m, 9000, nullptr, 0);
		const uint8_t zero[6] = {};
		ip("127.0.0.1", a);
		ip("255.0.0.0", m);
		set_nw_if_struct(
		    &ifs[2], -1, "lo", zero, a, m, 1500, nullptr, IF_NOARP | IF_LOOPBACK);
		for (size_t i = 0; i < 3; i++)
			ifs[i].index = i; // construct_stack does this
	}
	static static_route via(const char *prefix, const char *mask, const char *gw)
	{
		static_route r;
		ip(prefix, r.prefix);
		ip(mask, r.mask);
		ip(gw, r.gateway);
		return r;
	}
	route *lookup(const char *dst)
	{
		uint8_t d[4];
		ip(dst, d);
		route *r = nullptr;
		return get_route(t, d, &r) ? r : nullptr;
	}
};

TEST_F(Routes, ConnectedSubnetsAreOnLink)
{
	t = create_routing_table(ifs, 3, nullptr, 0);
	ASSERT_NE(t, nullptr);
	route *r = lookup("10.0.0.77");
	ASSERT_NE(r, nullptr);
	EXPECT_EQ(r->type, ROUTE_ONLINK);
	EXPECT_EQ(r->nw_if_id, 0u);
	EXPECT_EQ(r->prefix_len, 24);
	r = lookup("192.168.200.3");
	ASSERT_NE(r, nullptr);
	EXPECT_EQ(r->nw_if_id, 1u);
	EXPECT_EQ(r->mtu, 9000u) << "the route carries its interface's MTU";
}

TEST_F(Routes, OwnAddressesAndLoopbackRangeAreLocal)
{
	t = create_routing_table(ifs, 3, nullptr, 0);
	for (const char *a : {"10.0.0.2", "192.168.1.5", "127.0.0.1", "127.9.9.9"}) {
		route *r = lookup(a);
		ASSERT_NE(r, nullptr) << a;
		EXPECT_EQ(r->type, ROUTE_LOCAL) << a;
		EXPECT_EQ(r->nw_if_id, 2u) << a << " must go through loopback";
	}
	EXPECT_EQ(lookup("10.0.0.2")->prefix_len, 32) << "own address: a /32 beats the /24";
}

TEST_F(Routes, NoDefaultRouteMeansNoRoute)
{
	t = create_routing_table(ifs, 3, nullptr, 0);
	EXPECT_EQ(lookup("8.8.8.8"), nullptr);
}

TEST_F(Routes, LongestPrefixWins)
{
	static_route s[] = {via("0.0.0.0", "0.0.0.0", "10.0.0.1"),
			    via("172.16.0.0", "255.240.0.0", "192.168.1.1"),
			    via("172.20.1.0", "255.255.255.0", "10.0.0.254")};
	t = create_routing_table(ifs, 3, s, 3);
	ASSERT_NE(t, nullptr);

	route *r = lookup("8.8.8.8");
	ASSERT_NE(r, nullptr);
	EXPECT_EQ(r->type, ROUTE_VIA);
	EXPECT_EQ(r->gateway, u32("10.0.0.1"));
	EXPECT_EQ(r->nw_if_id, 0u) << "out of the interface whose subnet holds the gateway";

	r = lookup("172.17.3.4");
	ASSERT_NE(r, nullptr);
	EXPECT_EQ(r->gateway, u32("192.168.1.1")) << "/12 beats /0";
	EXPECT_EQ(r->nw_if_id, 1u);

	r = lookup("172.20.1.9");
	ASSERT_NE(r, nullptr);
	EXPECT_EQ(r->gateway, u32("10.0.0.254")) << "/24 beats /12";
	EXPECT_EQ(r->nw_if_id, 0u);

	r = lookup("10.0.0.9");
	ASSERT_NE(r, nullptr);
	EXPECT_EQ(r->type, ROUTE_ONLINK) << "a connected /24 beats the default route";
}

TEST_F(Routes, GatewayOffEverySubnetIsRejected)
{
	static_route s[] = {via("0.0.0.0", "0.0.0.0", "10.9.9.9")};
	EXPECT_EQ(create_routing_table(ifs, 3, s, 1), nullptr)
	    << "a gateway must be reachable on a connected subnet";
}

TEST_F(Routes, LocalAddressCheckCoversEveryInterface)
{
	uint8_t a[4];
	for (const char *s : {"10.0.0.2", "192.168.1.5", "127.0.0.1"}) {
		ip(s, a);
		EXPECT_TRUE(is_local_ipv4_addr(ifs, 3, a)) << s;
	}
	ip("10.0.0.3", a);
	EXPECT_FALSE(is_local_ipv4_addr(ifs, 3, a));
	ip("127.0.0.2", a);
	EXPECT_FALSE(is_local_ipv4_addr(ifs, 3, a)) << "only exact interface addresses";
}
