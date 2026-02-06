#include "types.h"
#include <stdio.h>

bool write_to_buffer(struct ring_buffer_t *buff, struct pkt_t *packet);
struct pkt_t *read_buffer(struct ring_buffer_t *buff);