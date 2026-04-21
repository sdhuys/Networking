#pragma once
#include "address_types.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define TCP_MSS_MAX 1460
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

struct ooo_seg {
	uint32_t start_seq;
	uint32_t end_seq;
};

struct tcp_conn_id {
	uint16_t loc_port;
	ipv4_address_t loc_addr;
	uint16_t extern_port;
	ipv4_address_t extern_addr;
};

#ifdef __cplusplus
extern "C" {
#endif

// 32-bit TCP sequence number comparisons
static inline bool tcp_seq_before(uint32_t a, uint32_t b)
{
	return (int32_t)(a - b) < 0;
}

static inline bool tcp_seq_after(uint32_t a, uint32_t b)
{
	return tcp_seq_before(b, a);
}

static inline bool tcp_seq_before_eq(uint32_t a, uint32_t b)
{
	return !tcp_seq_after(a, b);
}

static inline bool tcp_seq_after_eq(uint32_t a, uint32_t b)
{
	return !tcp_seq_before(a, b);
}

#ifdef __cplusplus
}
#endif
