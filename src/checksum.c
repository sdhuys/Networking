#include "checksum.h"

// ICMP checksum
uint16_t calc_checksum(void *data, size_t len)
{
	const uint8_t *bytes = data;
	uint32_t sum = 0;

	// Sum 16-bit words
	while (len >= 2) {
		sum += (bytes[0] << 8) | bytes[1];
		bytes += 2;
		len -= 2;
	}

	// Handle odd trailing byte
	if (len == 1)
		sum += bytes[0] << 8;

	// Fold carries
	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);

	return (uint16_t)~sum;
}


// length as given in ipv4 header = in 32bit units => no odd trailing byte possible
uint16_t calc_ipv4_checksum(struct ipv4_header_t *header, size_t header_len)
{
	// calc sum of all 16 bit units in header
	uint32_t sum = 0;
	uint16_t *ptr = (uint16_t *)header;

	for (uint i = 0; i < header_len * 2; i++)
		sum += ptr[i];

	// calc 16bit one's complement of sum (adding carries beyond 16 bits back)
	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);

	// one's complement
	return (uint16_t)~sum;
}