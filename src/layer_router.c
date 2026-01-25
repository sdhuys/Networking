#include "layer_router.h"

pkt_result pass_up_to_layer(struct nw_layer *self, char *up_name, struct pkt *packet)
{
	for (size_t i = 0; i < self->ups_count; i++)
		if (strcmp(self->ups[i]->name, up_name) == 0)
			return self->ups[i]->rcv_up(self->ups[i], packet);

	return LAYER_NAME_NOT_FOUND;
}