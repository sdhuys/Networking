#pragma once
#include "types.h"
#include <stdalign.h>

#define PKT_BUFF_POOL_SIZE 1000

#ifdef __cplusplus
extern "C" {
#endif

struct pkt_t *allocate_pkt();
void init_buffer_pool();
void release_pkt(struct pkt_t *pkt);
void retain_pkt(struct pkt_t *pkt);

#ifdef __cplusplus
}
#endif
