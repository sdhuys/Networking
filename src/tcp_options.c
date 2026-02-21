#include "tcp_options.h"
#include <arpa/inet.h>

#define TCPOPT_EOL 0
#define TCPOPT_NOP 1
#define TCPOPT_MSS 2
#define TCPOPT_WSCALE 3
#define TCPOPT_SACKOK 4
#define TCPOPT_SACK 5
#define TCPOPT_TS 8

#define MAX_TCP_WSCALE 14

bool parse_tcp_options(const unsigned char *opts, int opt_len, struct tcp_options *out)
{
	int i = 0;

	if (!opts || !out)
		return false;

	memset(out, 0, sizeof(*out));

	while (i < opt_len) {
		uint8_t kind = opts[i];

		// single-byte padding or end marker
		if (kind == TCPOPT_EOL)
			break;

		if (kind == TCPOPT_NOP) {
			i++;
			continue;
		}

		// multi-byte options

		// ensure safely reading length byte
		if (i + 1 >= opt_len)
			return false;

		uint8_t len = opts[i + 1];

		// ensure true multi-byte and no buffer overruns
		if (len < 2 || (i + len) > opt_len)
			return false;

		switch (kind) {
		case TCPOPT_MSS:
			if (len == 4) {
				uint16_t mss_val;
				memcpy(&mss_val, &opts[i + 2], 2);
				out->mss_present = true;
				out->mss = ntohs(mss_val);
			}
			break;

		case TCPOPT_WSCALE:
			if (len == 3) {
				out->wscale_present = true;
				uint8_t val = opts[i + 2];
				// RFC 7323: Clamp to 14
				out->wscale = (val > MAX_TCP_WSCALE) ? MAX_TCP_WSCALE : val;
			}
			break;

		case TCPOPT_SACKOK:
			if (len == 2)
				out->sack_permitted = true;
			break;

		case TCPOPT_SACK:
			// Length is 2 + (8 * num_blocks)
			if (len >= 10 && ((len - 2) % 8 == 0)) {
				int blocks_in_pkt = (len - 2) / 8;
				out->sack_block_count = (blocks_in_pkt > MAX_SACK_BLOCKS)
							    ? MAX_SACK_BLOCKS
							    : blocks_in_pkt;

				for (int b = 0; b < out->sack_block_count; b++) {
					uint32_t l, r;
					memcpy(&l, &opts[i + 2 + (b * 8)], 4);
					memcpy(&r, &opts[i + 6 + (b * 8)], 4);
					out->sacks[b].left = ntohl(l);
					out->sacks[b].right = ntohl(r);
				}
			}
			break;

		case TCPOPT_TS:
			if (len == 10) {
				uint32_t val, ecr;
				out->ts_present = true;
				memcpy(&val, &opts[i + 2], 4);
				memcpy(&ecr, &opts[i + 6], 4);
				out->tsval = ntohl(val);
				out->tsecr = ntohl(ecr);
			}
			break;

		default:
			// skip unknown options based on their reported length
			break;
		}

		i += len;
	}

	return true;
}
