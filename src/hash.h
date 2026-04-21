#pragma once
#include "address_types.h"
#include <stddef.h>
#include <stdint.h>

void hash_init(void);
uint32_t hash_table(const void *data, size_t len);
uint32_t hash_syncookie(ipv4_address_t local_addr,
			ipv4_address_t extern_addr,
			uint16_t local_port,
			uint16_t extern_port,
			uint64_t time);