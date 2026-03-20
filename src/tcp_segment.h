#pragma once
#include "tcp_common_types.h"
#include <stddef.h>
#include <stdint.h>

struct tcp_segment {
	struct tcp_header_no_options *header;
	struct tcp_options *options;
	size_t options_len;
	unsigned char *payload;
	uint32_t payload_len;
};

uint32_t seg_seq_len(struct tcp_segment *seg);