#pragma once
#include "types.h"

#define POOL_SIZE 100

#ifdef __cplusplus
extern "C"
{
#endif

struct pkt *allocate_pkt();
void init_buffer_pool();
void release_pkt(struct pkt *pkt);
void retain_pkt(struct pkt *pkt);

#ifdef __cplusplus
}
#endif
