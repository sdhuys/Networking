#pragma once
#include "tcp_common_types.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define TCP_OP_TS_LEN 12
#define TCP_HEADER_MAX_SACK 4

struct tcp_options {
	bool mss_present;
	uint16_t mss;

	bool wscale_present;
	uint8_t wscale;

	bool sack_permitted;

	int sack_block_count;
	struct ooo_seg sacks[MAX_SACK_BLOCKS];

	bool ts_present;
	uint32_t tsval;
	uint32_t tsecr;

	// set by calling parse_tcp_options() or tcp_options_len()
	uint8_t length;
};

#ifdef __cplusplus
extern "C" {
#endif

bool parse_tcp_options(const unsigned char *opts, int opt_len, struct tcp_options *out);
size_t calc_tcp_options_len(struct tcp_options *opt);
size_t tcp_serialize_options(unsigned char *buf, const struct tcp_options *opt);

#ifdef __cplusplus
}
#endif