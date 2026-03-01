#include "tcp_segment.h"

uint32_t seg_seq_len(struct tcp_segment *seg)
{
	uint32_t len = seg->payload_len;

	if (seg->header->flags & TCP_SYN)
		len++;
	if (seg->header->flags & TCP_FIN)
		len++;

	return len;
}