#include "types.h"

uint16_t calc_checksum(const struct checksum_chunk *chunks, size_t amount);
uint16_t calc_ipv4_checksum(struct ipv4_header_t *header, size_t header_len);