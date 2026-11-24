#include "nw_interface.h"
#include "buffer_pool.h"
#include "container_of.h"
#include "nw_interface.h"
#include "nw_layer.h"
#include "pkt.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <unistd.h>

// TODO: change to passing actual interface/fd to read from
void read_from_interface(struct nw_layer *if_layer)
{
	struct interface_context *interface_context =
	    ((struct interface_context *)if_layer->context);
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
		packet->if_index = 0;
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
pkt_result send_up_to_ethernet(struct nw_layer *if_layer, struct pkt *packet)
{
	return if_layer->ups[0]->rcv_up(if_layer->ups[0], packet);
}

pkt_result tap_transmit(struct interface_context *ctx, struct nw_interface *nif, struct pkt *p)
{
	FILE *log = fopen("io.txt", "a");
	if (log) {
		for (size_t i = 0; i < p->len; i++)
			fprintf(log, "%02X", p->data[i + p->offset]);
		fprintf(log, "\n");
		fclose(log);
	}

	ssize_t nwrite = write(nif->fd, (p->data + p->offset), p->len);

	if (nwrite < 0) {
		perror("Writing to TAP interface");
		return WRITE_ERROR;
	}
	return SENT;
}

pkt_result loopback_transmit(struct interface_context *ctx, struct nw_interface *nif, struct pkt *p)
{
	FILE *log = fopen("io.txt", "a");
	if (log) {
		for (size_t i = 0; i < p->len; i++)
			fprintf(log, "%02X", p->data[i + p->offset]);
		fprintf(log, "\n");
		fclose(log);
	}

	push_q(ctx->ingress_q, &p->q_node);
	return SENT;
}

pkt_result gen_interface_transmit(struct nw_layer *if_layer, struct pkt *packet)
{
	struct interface_context *if_cntx = (struct interface_context *)if_layer->context;
	struct nw_interface *nw_interfaces = if_cntx->interfaces;
	struct nw_interface *nw_if = &nw_interfaces[packet->if_index];
	return nw_if->transmit(if_cntx, nw_if, packet);
}

bool is_local_ipv4_addr(const struct nw_interface *nw_ifs, size_t count, const ipv4_address_t addr)
{
	for (size_t i = 0; i < count; i++)
		if (memcmp(nw_ifs[i].ipv4_addr, addr, IPV4_ADDR_LEN) == 0)
			return true;
	return false;
}

void set_nw_if_struct(struct nw_interface *nw_if,
		      int fd,
		      const char *if_name,
		      const mac_address_t mac_addr,
		      const ipv4_address_t ip_addr,
		      const ipv4_address_t subnet_mask,
		      const uint32_t mtu,
		      nw_if_transmit_fn tx_function,
		      uint32_t flags)
{
	nw_if->fd = fd;
	snprintf(nw_if->name, MAX_IF_NAME_LEN, "%s", if_name);
	memcpy(&nw_if->ipv4_addr, ip_addr, IPV4_ADDR_LEN);
	memcpy(nw_if->mac_addr, mac_addr, MAC_ADDR_LEN);
	nw_if->mtu = mtu;
	nw_if->transmit = tx_function;
	memcpy(&nw_if->subnet_mask, subnet_mask, IPV4_ADDR_LEN);
	nw_if->flags = flags;
}
