#include "buffer_pool.h"
#include "icmp.h"
#include "types.h"
#include <stdio.h>
#include <unistd.h>

void *ping_test(void *st)
{
	struct stack *s = (struct stack *)st;
	while (1) {
		struct pkt *p = allocate_pkt();
		p->protocol = P_ICMP;
		p->offset = PKT_SIZE - sizeof(struct icmp_header);
		p->len = sizeof(struct icmp_header);
		struct icmp_header *h = (struct icmp_header *)(p->data + p->offset);
		ipv4_address_t dns = {8, 8, 8, 8};
		memcpy(p->src_ip, s->local_address, IPV4_ADDR_LEN);
		memcpy(p->dest_ip, dns, IPV4_ADDR_LEN);
		h->type = ECHO_REQUEST;
		h->checksum = 0;
		struct checksum_chunk chunk = {.data = h, .len = p->len};
		h->checksum = htons(calc_checksum(&chunk, 1));
		s->icmp_layer->send_down(s->icmp_layer, p);
		sleep(5);
	}
}