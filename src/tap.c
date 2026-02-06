#include "tap.h"

int start_listening(struct nw_layer_t *interface)
{
	init_buffer_pool();
	int fd = ((struct interface_context_t *)interface->context)->interfaces[0].fd;

	for (;;) {
		struct pkt_t *packet = allocate_pkt();
		if (packet == NULL)
			continue;

		ssize_t nread = read(fd, packet->data, MAX_ETH_FRAME_SIZE);
		if (nread < 0) {
			release_pkt(packet);
			continue;
		}

		packet->len = (size_t)nread;
		packet->offset = 0;

		pkt_result result = interface->rcv_up(interface, packet);
		printf("%d \n\n", result);

		pthread_mutex_lock(&packet->lock);
		if (packet->dest_port == 9000) {
			FILE *log = fopen("in.txt", "a");
			if (log) {
				for (size_t i = 0; i < (size_t)nread; i++)
					fprintf(log, "%02X", packet->data[i]);
				fprintf(log, "\n");
				fclose(log);
			}
		}
		pthread_mutex_unlock(&packet->lock);

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
	struct nw_interface_t nw_if = nw_interfaces[packet->if_index];
	int fd = nw_if.fd;
	ssize_t nwrite = write(fd, (packet->data + packet->offset), packet->len);

	if (nwrite < 0) {
		perror("Writing to TAP interface");
		close(fd);

		return WRITE_ERROR;
	}

	FILE *log = fopen("out.txt", "a");
	if (log) {
		for (size_t i = 0; i < packet->len; i++)
			fprintf(log, "%02X", packet->data[i + packet->offset]);
		fprintf(log, "\n");
		fclose(log);
	}
	release_pkt(packet);
	return SENT;
}