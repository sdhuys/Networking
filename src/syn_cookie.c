#include "syn_cookie.h"

#define COOKIE_MSS_VAL_COUNT 4

static const uint16_t mss_enc_table[] = {TCP_MSS_DEFAULT_FALLBACK, 1300, 1440, TCP_MSS_MAX};
uint8_t mss_encode(uint16_t mss);
uint16_t mss_decode(uint8_t enc);

uint32_t generate_syn_cookie_iss(struct tcp_ipv4_listener *listener,
				 struct tcp_segment *seg,
				 struct pkt *p)
{
	uint32_t mss = seg->options->mss_present ? seg->options->mss : TCP_MSS_DEFAULT_FALLBACK;
	mss = mss_encode(mss);
	uint8_t mss_sack = (mss << 1) | seg->options->sack_permitted;

	// time in 64 seconds resolution
	uint64_t time = now_s() >> 6;

	uint32_t hash = hash_syncookie(
	    listener->local_addr, p->src_ip, listener->local_port, seg->header->dest_port, time);
	// encoded in 5 bits
	time &= 0x1F;

	uint32_t iss = time;
	iss = (iss << 3) | mss_sack;
	iss = (iss << 24) | hash;
	return iss;
}

uint8_t mss_encode(uint16_t mss)
{
	for (int i = COOKIE_MSS_VAL_COUNT - 1; i >= 0; i--) {
		if (mss >= mss_enc_table[i])
			return i;
	}
	return 0;
}

uint16_t mss_decode(uint8_t enc)
{
	if (enc >= COOKIE_MSS_VAL_COUNT)
		enc = COOKIE_MSS_VAL_COUNT - 1;
	return mss_enc_table[enc];
}

pkt_result syn_cookie_check_ack(struct tcp_ipv4_listener *listener,
				struct tcp_segment *seg,
				struct pkt *p)
{
	uint32_t cookie = seg->header->ack_num - 1;

	// top 5 bits: t
	// middle 3 bits: 2 bits encoded MSS, 1 bit sack_permitted
	// bottom 24 bits: hash
	uint32_t received_t_bits = (cookie >> 27);
	uint32_t received_mss_idx_sack = (cookie >> 24) & 7;
	uint32_t received_hash = cookie & 0x00FFFFFF;

	// current time in 64-second resolution.
	uint64_t now_t_full = now_s() >> 6;
	// 5 bit encoding
	uint8_t now_t_bits = (uint8_t)(now_t_full & 0x1F);

	// how many 64-second blocks have passed since the cookie was sent
	// due to wraparound delta 1 could mean any multiple of 32 * 64 seconds have passed
	// no way to filter out accidental very old connections (should be rare)
	uint8_t delta_t = (now_t_bits - received_t_bits) & 0x1F;

	// allow a window of 128 seconds (+ rare wraparound windows)
	if (delta_t >= 3)
		return TCP_SYN_COOKIE_EXPIRED;

	// reconstruct the original full timestamp used during generation.
	uint64_t original_t_full = now_t_full - delta_t;

	uint32_t expected_hash = hash_syncookie(listener->local_addr,  // Server IP
						p->src_ip,	       // Client IP
						listener->local_port,  // Server Port
						seg->header->src_port, // Client Port
						original_t_full // The RECONSTRUCTED full timestamp
	);

	if (received_hash != expected_hash)
		return TCP_SYN_COOKIE_INVALID;

	uint32_t mss = mss_decode(received_mss_idx_sack >> 1);
	bool sack_permitted = received_mss_idx_sack & 1;

	// create connection
	// send ack
	printf("\n\nSYN COOKIE ACK ESTABLISH CONNECTION!!! \n\n");
	return NOT_IMPLEMENTED_YET;
}