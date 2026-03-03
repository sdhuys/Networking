#include "tcp_options.h"
#include "tcp_conn_socket.h"
#include <arpa/inet.h>

#define TCP_OPT_EOL 0
#define TCP_OPT_NOP 1
#define TCP_OPT_MSS 2
#define TCP_OPT_WSCALE 3
#define TCP_OPT_SACKOK 4
#define TCP_OPT_SACK 5
#define TCP_OPT_TS 8

#define TCP_MAX_WSCALE 14
#define TCP_MAX_OPT_LEN 40

bool parse_tcp_options(const unsigned char *opts, int opt_len, struct tcp_options *out)
{
	int i = 0;

	if (!opts || !out || opt_len > 40)
		return false;

	memset(out, 0, sizeof(*out));
	out->length = opt_len;

	while (i < opt_len) {
		uint8_t kind = opts[i];

		// single-byte padding or end marker
		if (kind == TCP_OPT_EOL)
			break;

		if (kind == TCP_OPT_NOP) {
			i++;
			continue;
		}

		// ensure safely reading length byte
		if (i + 1 >= opt_len)
			return false;

		uint8_t len = opts[i + 1];

		// ensure true multi-byte and no buffer overruns
		if (len < 2 || (i + len) > opt_len)
			return false;

		switch (kind) {
		case TCP_OPT_MSS:
			if (len == 4) {
				uint16_t mss_val;
				memcpy(&mss_val, &opts[i + 2], 2);
				out->mss_present = true;
				out->mss = ntohs(mss_val);
			}
			break;

		case TCP_OPT_WSCALE:
			if (len == 3) {
				out->wscale_present = true;
				uint8_t val = opts[i + 2];
				// RFC 7323: Clamp to 14
				out->wscale = (val > TCP_MAX_WSCALE) ? TCP_MAX_WSCALE : val;
			}
			break;

		case TCP_OPT_SACKOK:
			if (len == 2)
				out->sack_permitted = true;
			break;

		case TCP_OPT_SACK:
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
					out->sacks[b].start_seq = ntohl(l);
					out->sacks[b].end_seq = ntohl(r);
				}
			}
			break;

		case TCP_OPT_TS:
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

size_t calc_tcp_options_len(struct tcp_options *opt)
{
	size_t len = 0;

	if (opt->mss_present)
		len += 4;

	if (opt->wscale_present)
		len += 3;

	if (opt->sack_permitted)
		len += 2;

	if (opt->ts_present) {
		while (len & 1)
			len++; // account for NOPs
		len += 10;
	}

	if (opt->sack_block_count > 0) {
		while (len & 3)
			len++; // account for NOPs
		int n = (opt->sack_block_count > MAX_SACK_BLOCKS) ? MAX_SACK_BLOCKS
								  : opt->sack_block_count;
		len += 2 + (8 * n);
	}

	// final padding to 32-bit boundary
	opt->length = (len + 3) & ~3;
	return opt->length;
}

static inline int enough_space(uint8_t *p, uint8_t *end, size_t n)
{
	return p + n <= end;
}

size_t tcp_serialize_options(unsigned char *buf, const struct tcp_options *opt)
{
    unsigned char *p = buf;
    unsigned char *end = buf + opt->length;

    if (opt->mss_present && enough_space(p, end, 4)) {
        *p++ = TCP_OPT_MSS;
        *p++ = 4;
        uint16_t mss = htons(opt->mss);
        memcpy(p, &mss, 2);
        p += 2;
    }

    if (opt->sack_permitted && enough_space(p, end, 2)) {
        *p++ = TCP_OPT_SACKOK;
        *p++ = 2;
    }

    if (opt->wscale_present && opt->wscale <= TCP_MAX_WSCALE && enough_space(p, end, 3)) {
        *p++ = TCP_OPT_WSCALE;
        *p++ = 3;
        *p++ = opt->wscale;
    }

    if (opt->ts_present) {
		// internal alignment
        while (((p - buf) & 1) && enough_space(p, end, 1)) *p++ = TCP_OPT_NOP;
        
        if (enough_space(p, end, 10)) {
            *p++ = TCP_OPT_TS;
            *p++ = 10;
            uint32_t ts = htonl(opt->tsval);
            uint32_t ecr = htonl(opt->tsecr);
            memcpy(p, &ts, 4); p += 4;
            memcpy(p, &ecr, 4); p += 4;
        }
    }

    if (opt->sack_block_count > 0) {
		// internal alignment
        while (((p - buf) & 3) && enough_space(p, end, 1)) *p++ = TCP_OPT_NOP;

        int n = (opt->sack_block_count > MAX_SACK_BLOCKS) ? MAX_SACK_BLOCKS : opt->sack_block_count;
        size_t sack_len = 2 + (8 * n);

        if (enough_space(p, end, sack_len)) {
            *p++ = TCP_OPT_SACK;
            *p++ = (uint8_t)sack_len;
            for (int i = 0; i < n; i++) {
                uint32_t left = htonl(opt->sacks[i].start_seq);
                uint32_t right = htonl(opt->sacks[i].end_seq);
                memcpy(p, &left, 4);  p += 4;
                memcpy(p, &right, 4); p += 4;
            }
        }
    }

    // final padding
    while (((p - buf) & 3) && enough_space(p, end, 1)) {
        *p++ = TCP_OPT_EOL;
    }

    return p - buf;
}