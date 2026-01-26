#include "types.h"

uint16_t calc_checksum(void *data, size_t len);
uint16_t calc_ipv4_checksum(struct ipv4_header_t *header, size_t header_len);