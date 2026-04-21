#pragma once
#include "address_types.h"
#include <stddef.h>
#include <stdint.h>

struct send_request {
	unsigned char *data;
	size_t len;
	ipv4_address_t dest_ip; // optional, only for UDP
	uint16_t dest_port;	// optional, only for UDP
};
