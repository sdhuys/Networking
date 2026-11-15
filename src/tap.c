#include "tap.h"
#include "container_of.h"
#include "buffer_pool.h"
#include "nw_interface.h"
#include "nw_layer.h"
#include "pkt.h"
#include "timer.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void read_from_interface(struct nw_layer *interface)
{
	struct interface_context *interface_context =
	    ((struct interface_context *)interface->context);
	int fd = interface_context->interfaces[0].fd;

	for (;;) {
		struct pkt *packet = allocate_pkt_wait();
		ssize_t nread = read(fd, packet->data, MAX_ETH_FRAME_SIZE);
		if (nread < 0) {
			printf("NO READ RELEASING \n");
			release_pkt(packet);
			continue;
		}
		packet->len = (size_t)nread;
		packet->offset = 0;
		FILE *log = fopen("io.txt", "a");
		if (log) {
			for (size_t i = 0; i < packet->len; i++)
				fprintf(log, "%02X", packet->data[i + packet->offset]);
			fprintf(log, "\n");
			fclose(log);
		}
		push_q(interface_context->ingress_q, &packet->q_node);
		release_pkt(packet);
	}
}

void process_ingress_q_packets(struct nw_layer *interface)
{
	struct interface_context *if_cntx = ((struct interface_context *)interface->context);
	struct queue *q = if_cntx->ingress_q;

	while (true) {
		struct queue_node *n = pop_q_blocking(q);
		if (!n)
			return; // INGRESS QUEUE STOPPED, STACK DISABLED
		struct pkt *p = CONTAINER_OF(n, struct pkt, q_node);

		pkt_result result = interface->rcv_up(interface, p);
		printf("LISTEN LOOP RELEASING \n");
		release_pkt(p);
		printf("%d \n\n", result);

	}
}

// No demuxing at this layer, no need for "pass_up_to_layer" usage
pkt_result send_up_to_ethernet(struct nw_layer *interface, struct pkt *packet)
{
	return interface->ups[0]->rcv_up(interface->ups[0], packet);
}

pkt_result write_to_interface(struct nw_layer *interface, struct pkt *packet)
{
	// context could contain array of interfaces
	struct interface_context *if_cntx = (struct interface_context *)interface->context;
	struct queue *q = if_cntx->ingress_q;
	struct nw_interface *nw_interfaces = if_cntx->interfaces;
	struct nw_interface nw_if = nw_interfaces[packet->if_index];
	int fd = nw_if.fd;

	FILE *log = fopen("io.txt", "a");
	if (log) {
		for (size_t i = 0; i < packet->len; i++)
			fprintf(log, "%02X", packet->data[i + packet->offset]);
		fprintf(log, "\n");
		fclose(log);
	}

	// mac address all zeros is sentinel value for loopback!
	bool loopback = ((packet->dest_mac[0] | packet->dest_mac[1] | packet->dest_mac[2] |
			  packet->dest_mac[3] | packet->dest_mac[4] | packet->dest_mac[5]) == 0);

	if (!loopback) {
		ssize_t nwrite = write(fd, (packet->data + packet->offset), packet->len);

		if (nwrite < 0) {
			perror("Writing to TAP interface");
			return WRITE_ERROR;
		}
	} else {
		push_q(q, &packet->q_node);
	}

	printf("SENT \n");
	return SENT;
}