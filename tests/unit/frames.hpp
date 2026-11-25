#pragma once
// Hand-built IPv4 / UDP / ICMP frames for the tests below TCP. Independent of the stack's code.

#include "wire.hpp"

#include <algorithm>
#include <cstdint>
#include <vector>

using namespace wire;

namespace frames
{
inline uint16_t be16(const std::vector<uint8_t> &f, size_t at)
{
	return (uint16_t)((f[at] << 8) | f[at + 1]);
}

// ones' complement sum over 16-bit big-endian words, not yet inverted
inline uint32_t sum16(const uint8_t *p, size_t n, uint32_t sum = 0)
{
	for (size_t i = 0; i + 1 < n; i += 2)
		sum += (uint32_t)((p[i] << 8) | p[i + 1]);
	if (n & 1)
		sum += (uint32_t)(p[n - 1] << 8);
	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);
	return sum;
}

inline void fix_ip_checksum(std::vector<uint8_t> &f)
{
	size_t ihl = (f[14] & 0x0F) * 4u;
	f[24] = f[25] = 0;
	uint16_t c = (uint16_t)~sum16(&f[14], ihl);
	f[24] = (uint8_t)(c >> 8);
	f[25] = (uint8_t)c;
}

// UDP checksum over pseudo header + UDP header + data, with the checksum field as it is
inline uint32_t udp_sum(const std::vector<uint8_t> &f)
{
	size_t ip = 14, ihl = (f[ip] & 0x0F) * 4u, udp = ip + ihl;
	uint16_t udp_len = be16(f, udp + 4);
	uint8_t pseudo[12];
	std::copy(&f[ip + 12], &f[ip + 20], pseudo); // src, dst
	pseudo[8] = 0;
	pseudo[9] = 17;
	pseudo[10] = (uint8_t)(udp_len >> 8);
	pseudo[11] = (uint8_t)udp_len;
	return sum16(&f[udp], udp_len, sum16(pseudo, 12));
}

inline std::vector<uint8_t> build_udp(const Mac &src_mac,
				      const Mac &dst_mac,
				      const Ip &src,
				      const Ip &dst,
				      uint16_t sport,
				      uint16_t dport,
				      const std::vector<uint8_t> &data)
{
	std::vector<uint8_t> f(14 + 20 + 8 + data.size(), 0);
	std::copy(dst_mac.begin(), dst_mac.end(), f.begin());
	std::copy(src_mac.begin(), src_mac.end(), f.begin() + 6);
	f[12] = 0x08;
	f[13] = 0x00;
	uint16_t tot = (uint16_t)(20 + 8 + data.size());
	f[14] = 0x45;
	f[16] = (uint8_t)(tot >> 8);
	f[17] = (uint8_t)tot;
	f[20] = 0x40; // DF
	f[22] = 64;
	f[23] = 17;
	std::copy(src.begin(), src.end(), f.begin() + 26);
	std::copy(dst.begin(), dst.end(), f.begin() + 30);
	fix_ip_checksum(f);
	size_t u = 34;
	uint16_t ulen = (uint16_t)(8 + data.size());
	f[u] = (uint8_t)(sport >> 8);
	f[u + 1] = (uint8_t)sport;
	f[u + 2] = (uint8_t)(dport >> 8);
	f[u + 3] = (uint8_t)dport;
	f[u + 4] = (uint8_t)(ulen >> 8);
	f[u + 5] = (uint8_t)ulen;
	std::copy(data.begin(), data.end(), f.begin() + u + 8);
	uint16_t c = (uint16_t)~udp_sum(f);
	if (c == 0)
		c = 0xFFFF;
	f[u + 6] = (uint8_t)(c >> 8);
	f[u + 7] = (uint8_t)c;
	return f;
}

// ICMP echo request (type 8) or reply (type 0); `bad_checksum` corrupts the checksum
inline std::vector<uint8_t> build_icmp_echo(const Mac &src_mac,
					    const Mac &dst_mac,
					    const Ip &src,
					    const Ip &dst,
					    uint8_t type,
					    uint16_t id,
					    uint16_t seq,
					    const std::vector<uint8_t> &data,
					    bool bad_checksum = false)
{
	std::vector<uint8_t> f(14 + 20 + 8 + data.size(), 0);
	std::copy(dst_mac.begin(), dst_mac.end(), f.begin());
	std::copy(src_mac.begin(), src_mac.end(), f.begin() + 6);
	f[12] = 0x08;
	uint16_t tot = (uint16_t)(20 + 8 + data.size());
	f[14] = 0x45;
	f[16] = (uint8_t)(tot >> 8);
	f[17] = (uint8_t)tot;
	f[22] = 64;
	f[23] = 1;
	std::copy(src.begin(), src.end(), f.begin() + 26);
	std::copy(dst.begin(), dst.end(), f.begin() + 30);
	fix_ip_checksum(f);
	size_t i = 34;
	f[i] = type;
	f[i + 4] = (uint8_t)(id >> 8);
	f[i + 5] = (uint8_t)id;
	f[i + 6] = (uint8_t)(seq >> 8);
	f[i + 7] = (uint8_t)seq;
	std::copy(data.begin(), data.end(), f.begin() + i + 8);
	uint16_t c = (uint16_t)~sum16(&f[i], 8 + data.size());
	if (bad_checksum)
		c ^= 0x0101;
	f[i + 2] = (uint8_t)(c >> 8);
	f[i + 3] = (uint8_t)c;
	return f;
}

inline bool is_icmp(const std::vector<uint8_t> &f)
{
	return f.size() >= 42 && ethertype(f) == 0x0800 && f[23] == 1;
}

inline bool is_udp(const std::vector<uint8_t> &f)
{
	return f.size() >= 42 && ethertype(f) == 0x0800 && f[23] == 17;
}
} // namespace frames
using namespace frames;
