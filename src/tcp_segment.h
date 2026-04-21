#pragma once
#include <stddef.h>
#include <stdint.h>

struct tcp_header_no_options;
struct tcp_options;

struct tcp_segment {
	struct tcp_header_no_options *header;
	struct tcp_options *options;
	size_t options_len;
	unsigned char *payload;
	uint32_t payload_len;
};

#ifdef __cplusplus
extern "C" {
#endif

uint32_t seg_seq_len(struct tcp_segment *seg);

#ifdef __cplusplus
}
#endif
