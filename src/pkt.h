#pragma once
#include "address_types.h"
#include "common_layer_types.h"
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

#define PKT_SIZE ((MAX_ETH_FRAME_SIZE / 64) + 1) * 64 // make it a multiple of 64

struct pkt {
	unsigned char *data;
	size_t offset; // Offset to the start of the current layer's header
	size_t len;    // Packet length from current offset (current layer's length)

	pthread_mutex_t lock;
	uint16_t pool_index; // for debugging
	uint8_t ref_count;

	int if_index;
	uint16_t ethertype;
	uint8_t protocol;
	mac_address_t dest_mac;

	ipv4_address_t src_ip;
	ipv4_address_t dest_ip;

	// TRANSPORT LAYER metadata
	// apart from src and dest ports for UDP, these fields are only ever used to store metadata
	// for outgoing packets
	uint16_t src_port;
	uint16_t dest_port;
	uint32_t tcp_seq;
	uint32_t tcp_ack;
	uint8_t tcp_flags;
	uint16_t rcv_window;
	struct tcp_options *tcp_options;
	struct route *route;
};