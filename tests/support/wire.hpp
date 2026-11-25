#pragma once
// Builds and parses Ethernet/IPv4/TCP frames independently of the stack's own code,
// so a bug in the stack's serialisation or checksums can't hide itself in the tests.

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace wire
{

using Mac = std::array<uint8_t, 6>;
using Ip = std::array<uint8_t, 4>;

Ip ip(const std::string &dotted);
std::string ip_str(const Ip &a);

enum : uint8_t {
	FIN = 0x01,
	SYN = 0x02,
	RST = 0x04,
	PSH = 0x08,
	ACK = 0x10,
	URG = 0x20,
	ECE = 0x40,
	CWR = 0x80
};

struct TcpOptions {
	std::optional<uint16_t> mss;
	std::optional<uint8_t> wscale;
	bool sack_permitted = false;
	std::optional<std::pair<uint32_t, uint32_t>> ts;  // TSval, TSecr
	std::vector<std::pair<uint32_t, uint32_t>> sacks; // [left, right) edges
};

struct TcpSegment {
	Mac src_mac{}, dst_mac{};
	Ip src_ip{}, dst_ip{};
	uint16_t src_port = 0, dst_port = 0;
	uint32_t seq = 0, ack = 0;
	uint8_t flags = 0;
	uint16_t window = 0;
	TcpOptions opts;
	std::vector<uint8_t> payload;

	// filled in by parse(), describing the frame as it was on the wire
	size_t frame_len = 0;
	size_t options_len = 0;	 // bytes of options area
	uint8_t data_offset = 0; // in 32-bit words
	uint16_t ip_total_length = 0;
	bool ip_checksum_ok = false;
	bool tcp_checksum_ok = false;
	bool options_well_formed = false;
	uint8_t ttl = 0;
	bool dont_fragment = false;

	uint32_t seq_len() const; // payload + SYN + FIN
	std::string describe() const;
};

std::vector<uint8_t> build(const TcpSegment &s);
std::optional<TcpSegment> parse(const std::vector<uint8_t> &frame); // nullopt if not IPv4/TCP

// Ethernet type / ARP helpers
uint16_t ethertype(const std::vector<uint8_t> &frame);
bool is_arp_request_for(const std::vector<uint8_t> &frame, const Ip &target);
std::vector<uint8_t> build_arp_reply(const Mac &src_mac,
				     const Ip &src_ip,
				     const Mac &dst_mac,
				     const Ip &dst_ip);
std::vector<uint8_t> build_arp_request(const Mac &src_mac, const Ip &src_ip, const Ip &target_ip);

// sequence arithmetic (RFC 1982 style)
inline bool seq_lt(uint32_t a, uint32_t b)
{
	return (int32_t)(a - b) < 0;
}
inline bool seq_le(uint32_t a, uint32_t b)
{
	return (int32_t)(a - b) <= 0;
}

} // namespace wire
