#include "wire.hpp"

#include <arpa/inet.h>
#include <cstdio>
#include <cstring>
#include <sstream>
#include <stdexcept>

namespace wire
{

Ip ip(const std::string &dotted)
{
	in_addr a{};
	if (inet_pton(AF_INET, dotted.c_str(), &a) != 1)
		throw std::runtime_error("bad ip " + dotted);
	Ip out;
	std::memcpy(out.data(), &a.s_addr, 4);
	return out;
}

std::string ip_str(const Ip &a)
{
	char buf[16];
	std::snprintf(buf, sizeof buf, "%u.%u.%u.%u", a[0], a[1], a[2], a[3]);
	return buf;
}

static void put16(std::vector<uint8_t> &v, size_t at, uint16_t x)
{
	v[at] = x >> 8;
	v[at + 1] = x & 0xFF;
}
static void put32(std::vector<uint8_t> &v, size_t at, uint32_t x)
{
	v[at] = x >> 24;
	v[at + 1] = (x >> 16) & 0xFF;
	v[at + 2] = (x >> 8) & 0xFF;
	v[at + 3] = x & 0xFF;
}
static uint16_t get16(const uint8_t *p)
{
	return (uint16_t)((p[0] << 8) | p[1]);
}
static uint32_t get32(const uint8_t *p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

// RFC 1071 one's complement sum over 16-bit big-endian words
static uint32_t sum16(const uint8_t *p, size_t n, uint32_t acc = 0)
{
	for (size_t i = 0; i + 1 < n; i += 2)
		acc += (uint32_t)((p[i] << 8) | p[i + 1]);
	if (n & 1)
		acc += (uint32_t)(p[n - 1] << 8);
	return acc;
}
static uint16_t fold(uint32_t acc)
{
	while (acc >> 16)
		acc = (acc & 0xFFFF) + (acc >> 16);
	return (uint16_t)~acc;
}

static uint16_t tcp_checksum(const Ip &src, const Ip &dst, const uint8_t *tcp, size_t len)
{
	uint8_t pseudo[12];
	std::memcpy(pseudo, src.data(), 4);
	std::memcpy(pseudo + 4, dst.data(), 4);
	pseudo[8] = 0;
	pseudo[9] = 6;
	pseudo[10] = len >> 8;
	pseudo[11] = len & 0xFF;
	return fold(sum16(tcp, len, sum16(pseudo, 12)));
}

uint32_t TcpSegment::seq_len() const
{
	return (uint32_t)payload.size() + ((flags & SYN) ? 1 : 0) + ((flags & FIN) ? 1 : 0);
}

std::string TcpSegment::describe() const
{
	std::ostringstream o;
	o << ip_str(src_ip) << ":" << src_port << " > " << ip_str(dst_ip) << ":" << dst_port
	  << " [";
	const char *names[] = {"F", "S", "R", "P", ".", "U", "E", "C"};
	for (int i = 0; i < 8; i++)
		if (flags & (1 << i))
			o << names[i];
	o << "] seq " << seq << " ack " << ack << " win " << window << " len " << payload.size();
	if (opts.mss)
		o << " mss " << *opts.mss;
	if (opts.wscale)
		o << " ws " << (int)*opts.wscale;
	if (opts.sack_permitted)
		o << " sackOK";
	if (opts.ts)
		o << " ts " << opts.ts->first << "/" << opts.ts->second;
	for (auto &b : opts.sacks)
		o << " sack " << b.first << "-" << b.second;
	return o.str();
}

static std::vector<uint8_t> encode_options(const TcpOptions &o)
{
	std::vector<uint8_t> v;
	if (o.mss) {
		v.insert(v.end(), {2, 4, (uint8_t)(*o.mss >> 8), (uint8_t)(*o.mss & 0xFF)});
	}
	if (o.sack_permitted && o.ts) {
		// the common Linux layout: SACK-permitted + timestamps in 12 bytes
		v.insert(v.end(), {4, 2, 8, 10});
		for (uint32_t x : {o.ts->first, o.ts->second})
			v.insert(v.end(),
				 {(uint8_t)(x >> 24),
				  (uint8_t)(x >> 16),
				  (uint8_t)(x >> 8),
				  (uint8_t)x});
	} else {
		if (o.sack_permitted)
			v.insert(v.end(), {1, 1, 4, 2});
		if (o.ts) {
			v.insert(v.end(), {1, 1, 8, 10});
			for (uint32_t x : {o.ts->first, o.ts->second})
				v.insert(v.end(),
					 {(uint8_t)(x >> 24),
					  (uint8_t)(x >> 16),
					  (uint8_t)(x >> 8),
					  (uint8_t)x});
		}
	}
	if (o.wscale)
		v.insert(v.end(), {1, 3, 3, *o.wscale});
	if (!o.sacks.empty()) {
		v.insert(v.end(), {1, 1, 5, (uint8_t)(2 + 8 * o.sacks.size())});
		for (auto &b : o.sacks)
			for (uint32_t x : {b.first, b.second})
				v.insert(v.end(),
					 {(uint8_t)(x >> 24),
					  (uint8_t)(x >> 16),
					  (uint8_t)(x >> 8),
					  (uint8_t)x});
	}
	while (v.size() % 4)
		v.push_back(0);
	return v;
}

std::vector<uint8_t> build(const TcpSegment &s)
{
	std::vector<uint8_t> opt = encode_options(s.opts);
	if (opt.size() > 40)
		throw std::runtime_error("test built more than 40 bytes of TCP options");
	size_t tcp_len = 20 + opt.size() + s.payload.size();
	size_t ip_len = 20 + tcp_len;
	std::vector<uint8_t> f(14 + ip_len, 0);

	std::memcpy(&f[0], s.dst_mac.data(), 6);
	std::memcpy(&f[6], s.src_mac.data(), 6);
	put16(f, 12, 0x0800);

	size_t ipo = 14;
	f[ipo] = 0x45;
	put16(f, ipo + 2, (uint16_t)ip_len);
	put16(f, ipo + 6, 0x4000); // DF
	f[ipo + 8] = 64;
	f[ipo + 9] = 6;
	std::memcpy(&f[ipo + 12], s.src_ip.data(), 4);
	std::memcpy(&f[ipo + 16], s.dst_ip.data(), 4);
	put16(f, ipo + 10, fold(sum16(&f[ipo], 20)));

	size_t t = ipo + 20;
	put16(f, t, s.src_port);
	put16(f, t + 2, s.dst_port);
	put32(f, t + 4, s.seq);
	put32(f, t + 8, s.ack);
	f[t + 12] = (uint8_t)(((20 + opt.size()) / 4) << 4);
	f[t + 13] = s.flags;
	put16(f, t + 14, s.window);
	if (!opt.empty())
		std::memcpy(&f[t + 20], opt.data(), opt.size());
	if (!s.payload.empty())
		std::memcpy(&f[t + 20 + opt.size()], s.payload.data(), s.payload.size());
	put16(f, t + 16, tcp_checksum(s.src_ip, s.dst_ip, &f[t], tcp_len));
	return f;
}

static bool decode_options(const uint8_t *p, size_t n, TcpOptions &o)
{
	size_t i = 0;
	while (i < n) {
		uint8_t kind = p[i];
		if (kind == 0)
			return true; // end of list
		if (kind == 1) {
			i++;
			continue;
		}
		if (i + 1 >= n)
			return false;
		uint8_t len = p[i + 1];
		if (len < 2 || i + len > n)
			return false;
		switch (kind) {
		case 2:
			if (len != 4)
				return false;
			o.mss = get16(p + i + 2);
			break;
		case 3:
			if (len != 3)
				return false;
			o.wscale = p[i + 2];
			break;
		case 4:
			if (len != 2)
				return false;
			o.sack_permitted = true;
			break;
		case 5:
			if ((len - 2) % 8 != 0)
				return false;
			for (size_t b = 0; b < (size_t)(len - 2) / 8; b++)
				o.sacks.push_back(
				    {get32(p + i + 2 + 8 * b), get32(p + i + 6 + 8 * b)});
			break;
		case 8:
			if (len != 10)
				return false;
			o.ts = {get32(p + i + 2), get32(p + i + 6)};
			break;
		default:
			break; // unknown options are skipped by length
		}
		i += len;
	}
	return true;
}

uint16_t ethertype(const std::vector<uint8_t> &f)
{
	return f.size() >= 14 ? get16(&f[12]) : 0;
}

std::optional<TcpSegment> parse(const std::vector<uint8_t> &f)
{
	if (f.size() < 14 + 20 + 20 || ethertype(f) != 0x0800)
		return std::nullopt;
	const uint8_t *ipp = &f[14];
	if ((ipp[0] >> 4) != 4 || ipp[9] != 6)
		return std::nullopt;
	size_t ihl = (ipp[0] & 0x0F) * 4;
	TcpSegment s;
	s.frame_len = f.size();
	std::memcpy(s.dst_mac.data(), &f[0], 6);
	std::memcpy(s.src_mac.data(), &f[6], 6);
	s.ip_total_length = get16(ipp + 2);
	s.dont_fragment = (get16(ipp + 6) & 0x4000) != 0;
	s.ttl = ipp[8];
	std::memcpy(s.src_ip.data(), ipp + 12, 4);
	std::memcpy(s.dst_ip.data(), ipp + 16, 4);
	s.ip_checksum_ok = fold(sum16(ipp, ihl)) == 0;

	// TCP length from the IP header, as a receiver must compute it
	if (s.ip_total_length < ihl + 20 || 14 + (size_t)s.ip_total_length > f.size())
		return s; // malformed: fields left default, checks fail in the caller
	const uint8_t *t = ipp + ihl;
	size_t tcp_len = s.ip_total_length - ihl;
	s.src_port = get16(t);
	s.dst_port = get16(t + 2);
	s.seq = get32(t + 4);
	s.ack = get32(t + 8);
	s.data_offset = t[12] >> 4;
	s.flags = t[13];
	s.window = get16(t + 14);
	size_t hdr = (size_t)s.data_offset * 4;
	if (hdr < 20 || hdr > tcp_len)
		return s;
	s.options_len = hdr - 20;
	s.options_well_formed = decode_options(t + 20, s.options_len, s.opts);
	s.payload.assign(t + hdr, t + tcp_len);
	// summing a correct segment including its own checksum gives 0 after the final inversion
	s.tcp_checksum_ok = tcp_checksum(s.src_ip, s.dst_ip, t, tcp_len) == 0;
	return s;
}

bool is_arp_request_for(const std::vector<uint8_t> &f, const Ip &target)
{
	if (f.size() < 42 || ethertype(f) != 0x0806)
		return false;
	const uint8_t *a = &f[14];
	return get16(a + 6) == 1 && std::memcmp(a + 24, target.data(), 4) == 0;
}

static std::vector<uint8_t> arp_frame(uint16_t op,
				      const Mac &eth_dst,
				      const Mac &src_mac,
				      const Ip &src_ip,
				      const Mac &tgt_mac,
				      const Ip &tgt_ip)
{
	std::vector<uint8_t> f(42, 0);
	std::memcpy(&f[0], eth_dst.data(), 6);
	std::memcpy(&f[6], src_mac.data(), 6);
	put16(f, 12, 0x0806);
	put16(f, 14, 1);
	put16(f, 16, 0x0800);
	f[18] = 6;
	f[19] = 4;
	put16(f, 20, op);
	std::memcpy(&f[22], src_mac.data(), 6);
	std::memcpy(&f[28], src_ip.data(), 4);
	std::memcpy(&f[32], tgt_mac.data(), 6);
	std::memcpy(&f[38], tgt_ip.data(), 4);
	return f;
}

std::vector<uint8_t> build_arp_reply(const Mac &src_mac,
				     const Ip &src_ip,
				     const Mac &dst_mac,
				     const Ip &dst_ip)
{
	return arp_frame(2, dst_mac, src_mac, src_ip, dst_mac, dst_ip);
}

std::vector<uint8_t> build_arp_request(const Mac &src_mac, const Ip &src_ip, const Ip &target_ip)
{
	Mac bcast;
	bcast.fill(0xFF);
	return arp_frame(1, bcast, src_mac, src_ip, Mac{}, target_ip);
}

} // namespace wire
