#include "buffer_pool.h"

// could/should(?) be part of tap context instead of static variables
// ok for now
static unsigned char buffer_pool[MAX_ETH_FRAME_SIZE][POOL_SIZE];
static struct pkt pkt_pool[POOL_SIZE];
static struct pkt *free_pkt_stack[POOL_SIZE];
static int top_free_index;

void init_buffer_pool()
{
    for (int i = 0; i < POOL_SIZE; i++)
    {
        pkt_pool[i].data = buffer_pool[i];
        free_pkt_stack[i] = &pkt_pool[i];
    }
    top_free_index = POOL_SIZE - 1;
}

struct pkt *allocate_pkt()
{
    if (top_free_index < 0)
        return NULL;
    struct pkt *p = free_pkt_stack[top_free_index--];
    p->ref_count = 1;
    return p;
}

// called at the end of write_to_tap
// called in listening loop when result != SENT
void release_pkt(struct pkt *pkt)
{
    if (--pkt->ref_count <= 0)
        free_pkt_stack[++top_free_index] = pkt;
}

// called in any layer that needs to keep the packet
// e.g. for queuing
void retain_pkt(struct pkt *pkt)
{
    pkt->ref_count++;
}