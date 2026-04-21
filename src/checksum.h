#pragma once
#include <stddef.h>
#include <stdint.h>

struct ipv4_header;

struct checksum_chunk {
	const void *data;
	size_t len;
};

#ifdef __cplusplus
extern "C" {
#endif

uint16_t calc_checksum(const struct checksum_chunk *chunks, size_t amount);
uint16_t calc_ipv4_checksum(struct ipv4_header *header, size_t header_len);

#ifdef __cplusplus
}
#endif
