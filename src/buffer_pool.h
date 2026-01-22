#pragma once
#include "types.h"

#define POOL_SIZE 100

struct pkt *allocate_pkt();
void init_buffer_pool();
void release_pkt(struct pkt *pkt);