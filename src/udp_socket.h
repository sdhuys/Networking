#pragma once
#include "buffer_pool.h"
#include "ring_buffer.h"
#include "socket_manager.h"
#include "types.h"
#include <stdlib.h>

extern const struct socket_ops_t udp_socket_ops;

struct udp_ipv4_socket_t *create_udp_socket(uint16_t port);
struct ring_buffer_t *create_init_ring_buffer();
void destroy_udp_socket(struct udp_ipv4_socket_t *socket);
void retain_udp_socket(struct udp_ipv4_socket_t *socket);
void release_udp_socket(struct udp_ipv4_socket_t *socket);

pkt_result write_up_to_rcv_buffer(struct udp_ipv4_socket_t *socket, struct pkt_t *packet);
bool write_to_buffer(struct ring_buffer_t *buff, struct pkt_t *packet);
struct pkt_t *read_buffer(struct ring_buffer_t *buff);

bool udp_is_rcv_queued(void *s);
void udp_set_rcv_queued(void *s, bool v);
bool udp_is_snd_queued(void *s);
void udp_set_snd_queued(void *s, bool v);
void udp_retain(void *s);
void udp_release(void *s);
bool udp_write_to_snd_buffer(void *s, struct send_request_t req);
struct pkt_t *udp_read_rcv_buffer(void *s);
void lock_socket(void *s);
void unlock_socket(void *s);
