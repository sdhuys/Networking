#pragma once

#define PKT_BUFF_POOL_SIZE 1000

struct pkt;
struct queue_node;

#ifdef __cplusplus
extern "C" {
#endif

struct pkt *allocate_pkt();
void init_buffer_pool();
void release_pkt(struct pkt *pkt);
void retain_pkt(struct pkt *pkt);
void q_release_pkt(struct queue_node* n);
void q_retain_pkt(struct queue_node* n);


#ifdef __cplusplus
}
#endif
