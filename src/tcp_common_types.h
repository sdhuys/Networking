#pragma once
#include "stdint.h"
#include "types.h"

#define TCP_MSS_MAX 1460
#define TCP_MSS_TS 1448 // max segment with timestamps enabled
#define TCP_MSS_DEFAULT_FALLBACK 536
#define MAX_SACK_BLOCKS 4

#define TCP_FIN 0x01 // 0000 0001
#define TCP_SYN 0x02 // 0000 0010
#define TCP_RST 0x04 // 0000 0100
#define TCP_PSH 0x08 // 0000 1000
#define TCP_ACK 0x10 // 0001 0000
#define TCP_URG 0x20 // 0010 0000
#define TCP_ECE 0x40 // 0100 0000
#define TCP_CWR 0x80 // 1000 0000

struct tcp_header_no_options {
	uint16_t src_port;
	uint16_t dest_port;
	uint32_t seq_num;
	uint32_t ack_num;
	uint8_t data_offset; // (4bits) the number of 32 bit words in the header. 5 => no options
	uint8_t flags;	     // CWR, ECE, URG, ACK, PSH, RST, SYN, FIN
	uint16_t window;
	uint16_t checksum;
	uint16_t urg_ptr;
} __attribute__((packed));

struct sack_block {
	uint32_t left;
	uint32_t right;
};

struct tcp_options {
	bool mss_present;
	uint16_t mss;

	bool wscale_present;
	uint8_t wscale;

	bool sack_permitted; // SYN/SYN-ACK handshake

	int sack_block_count; // Data ACKs
	struct sack_block sacks[MAX_SACK_BLOCKS];

	bool ts_present;
	uint32_t tsval;
	uint32_t tsecr;
};
struct tcp_segment {
	struct tcp_header_no_options *header;
	struct tcp_options options;
	size_t options_len;
	unsigned char *payload;
	size_t payload_len;
};
