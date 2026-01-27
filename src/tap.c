#include "tap.h"

int start_listening(int fd, struct nw_layer_t *interface)
{
	init_buffer_pool();
	for (;;) {
		struct pkt_t *packet = allocate_pkt();
		ssize_t nread = read(fd, packet->data, MAX_ETH_FRAME_SIZE);
		if (nread < 0)
			continue;

		packet->len = (size_t)nread;
		packet->offset = 0;

		pkt_result result = interface->rcv_up(interface, packet);
		printf("%d \n\n", result);
		if (result != SENT)
			release_pkt(packet);
	}
}

// No demuxing at this layer, no need for "pass_up_to_layer" usage
pkt_result send_up_to_ethernet(struct nw_layer_t *interface, struct pkt_t *packet)
{
	return interface->ups[0]->rcv_up(interface->ups[0], packet);
}

pkt_result write_to_interface(struct nw_layer_t *interface, struct pkt_t *packet)
{
	// context could contain array of interfaces
	struct interface_context_t *if_cntx = (struct interface_context_t *)interface->context;
	struct nw_interface_t *nw_interfaces = if_cntx->interfaces;
	struct nw_interface_t nw_if = nw_interfaces[packet->intrfc_indx];
	int fd = nw_if.fd;
	ssize_t nwrite = write(fd, packet->data, packet->len);

	if (nwrite < 0) {
		perror("Writing to TAP interface");
		close(fd);

		return WRITE_ERROR;
	}

	FILE *log = fopen("out.txt", "a");
	if (log) {
		for (size_t i = 0; i < packet->len; i++)
			fprintf(log, "%02X", packet->data[i]);
		fprintf(log, "\n");
		fclose(log);
	}
	release_pkt(packet);
	return SENT;
}