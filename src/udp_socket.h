#pragma once
#include "buffer_pool.h"
#include "pkt_ring_buffer.h"
#include "socket_manager.h"
#include "types.h"
#include <stdlib.h>

#define UDP_RING_BUFF_SIZE 256

extern const struct socket_ops udp_socket_ops;

struct udp_ipv4_socket *create_udp_socket(uint16_t port, struct stack *stack);
void destroy_udp_socket(struct udp_ipv4_socket *socket);
void retain_udp_socket(struct udp_ipv4_socket *socket);
void release_udp_socket(struct udp_ipv4_socket *socket);

pkt_result write_up_to_rcv_buffer(struct udp_ipv4_socket *socket, struct pkt *packet);

bool udp_is_snd_queued(void *s);
void udp_set_snd_queued(void *s, bool v);
void udp_retain(void *s);
void udp_release(void *s);
bool udp_write_to_snd_buffer(struct stack *stack, void *s, struct send_request req);
int udp_read_rcv_buffer(void *s, size_t len, unsigned char *buff);
int udp_read_rcv_buffer_from(
    void *s, size_t len, unsigned char *buff, ipv4_address addr_out, uint16_t *port_out);
void lock_socket(void *s);
void unlock_socket(void *s);
struct pkt *udp_next_snd_pkt(void *s);
pkt_result udp_send_pkt(struct stack *stack, struct pkt *pkt);
void udp_close_sock(struct stack *stack, void *s);

typedef enum { UDP_LISTEN, UDP_CLOSED } udp_socket_state;

struct udp_ipv4_socket {
	uint16_t local_port;
	ipv4_address local_addr;
	struct pkt_ring_buffer *rcv_buffer; // stack writes, app consumes
	struct pkt_ring_buffer *snd_buffer; // app writes, stack consumes
	udp_socket_state state;
	uint32_t ref_count;
	bool queued_for_snd;
	pthread_mutex_t lock;
};