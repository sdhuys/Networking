#pragma once
#include "address_types.h"
#include "pkt_result.h"
#include <stdbool.h>
#include <stdint.h>

#define IPV4_V 4
#define IPV4_HEADER_NO_OPTIONS_LEN 5 // length in 32bits (5 = 5 * 32 bits)
#define IPV4_TTL_DEFAULT 64

struct pkt;
struct nw_layer;

struct ipv4_context {
	struct nw_layer *arp_layer;
	ipv4_address_t stack_ipv4_addr;
	struct routing_table *routing_table;
};

struct ipv4_header {
	// upper 4 bits = version (4 for ipv4)
	// lower 4 bits = internet header-length (unit = 32bits, min value = 5)
	unsigned char version_ihl;
	// upper 6 bits = dscp, lower 2 bits = ecn. IGNORED, NOT SUPPORTED!
	unsigned char dscp_ecn;
	uint16_t total_length;
	uint16_t id;
	// upper 3 bits = flags => first = reserved, second = don't fragment, third
	// = more fragments lower 13 bits = fragment offset
	uint16_t flags_fragment_offset;
	unsigned char ttl;
	unsigned char protocol;
	uint16_t header_checksum;
	ipv4_address_t src_ip;
	ipv4_address_t dest_ip;
} __attribute__((packed));

struct ipv4_pseudo_header {
	ipv4_address_t src_ip;
	ipv4_address_t dest_ip;
	uint8_t padding;
	uint8_t protocol;
	uint16_t len;
} __attribute__((packed));

#ifdef __cplusplus
extern "C" {
#endif

pkt_result receive_ipv4_up(struct nw_layer *self, struct pkt *packet);
pkt_result send_ipv4_down(struct nw_layer *self, struct pkt *packet);
bool relevant_destination_ip(ipv4_address_t dest_ip, struct nw_layer *self);
void write_ipv4_header(struct ipv4_header *header, struct pkt *packet);

#ifdef __cplusplus
}
#endif
