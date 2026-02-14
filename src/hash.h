#pragma once
#include "stdbool.h"
#include "stddef.h"
#include "stdint.h"
#include "string.h"
#include <stdio.h>
#include <stdlib.h>

void hash_init(void);
uint32_t hash_table(const unsigned char *data, size_t len);
uint32_t hash_syncookie(const unsigned char *data, size_t len, uint32_t time);