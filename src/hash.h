#pragma once
#include "address_types.h"
#include "stdbool.h"
#include "stddef.h"
#include "stdint.h"
#include "string.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/random.h>

void hash_init(void);
uint32_t hash_table(const void *data, size_t len);
uint32_t hash_syncookie(ipv4_address local_addr,
			ipv4_address extern_addr,
			uint16_t local_port,
			uint16_t extern_port,
			uint64_t time);