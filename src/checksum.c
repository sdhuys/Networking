#include "checksum.h"

#include <stdint.h>
#include <stddef.h>
#include <arpa/inet.h> // For htons

// checksum over non-contiguous chunks of data
uint16_t calc_checksum(const struct checksum_chunk *chunks, size_t amount)
{
    uint32_t sum = 0;
    int have_odd = 0;
    uint8_t odd_byte = 0;

    for (size_t i = 0; i < amount; i++) {
        const uint8_t *ptr = chunks[i].data;
        size_t len = chunks[i].len;

		// prepend previous chunk's odd byte to current chunk
        if (have_odd && len) {
            sum += (odd_byte << 8) | *ptr++;
            len--;
            have_odd = 0;
        }

        while (len >= 2) {
            sum += (ptr[0] << 8) | ptr[1];
            ptr += 2;
            len -= 2;
        }

		// store current chunk's odd byte
        if (len) {
            odd_byte = *ptr;
            have_odd = 1;
        }
    }

	// handle leftover trailing odd byte
    if (have_odd)
        sum += odd_byte << 8;

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return (uint16_t)~sum;
}

// length as given in ipv4 header = in 32bit words => no odd trailing byte possible
uint16_t calc_ipv4_checksum(struct ipv4_header_t *header, size_t header_len)
{
	// calc sum of all 16 bit words in header
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