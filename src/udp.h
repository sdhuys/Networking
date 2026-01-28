#pragma once
#include "checksum.h"
#include "layer_router.h"
#include "types.h"
#include <arpa/inet.h>
#include <assert.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <assert.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

pkt_result send_udp_down(struct nw_layer_t *self, struct pkt_t *packet);
pkt_result receive_udp_up(struct nw_layer_t *self, struct pkt_t *packet);
bool validate_checksum(struct udp_header_t *header, struct pkt_t *packet);
struct udp_ipv4_socket_t *create_udp_socket(struct udp_context_t *context, uint16_t port);
void destroy_udp_socket(struct udp_ipv4_socket_t *socket);
struct udp_ipv4_socket_t *query_hashtable(struct udp_ipv4_sckt_htable_t *htable,
					  uint16_t dest_port);
bool remove_from_hashtable(struct udp_ipv4_sckt_htable_t *htable, struct udp_ipv4_socket_t *socket);
bool add_to_hashtable(struct udp_ipv4_sckt_htable_t *htable, struct udp_ipv4_socket_t *socket);
void retain_socket(struct udp_ipv4_socket_t *socket);
void release_socket(struct udp_ipv4_socket_t *socket);
uint32_t calc_hash(uint16_t port, struct udp_ipv4_sckt_htable_t *htable);
pkt_result write_to_udp_socket(struct udp_ipv4_socket_t *socket, struct pkt_t *packet);

#ifdef __cplusplus
}
#endif
