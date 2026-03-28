#include "app.h"
#include <stdio.h>

void client_app(struct stack *stack)
{
	ipv4_address_t server = {192, 168, 100, 2};
	int tcp_9000 = tcp_connect(stack, 1234, 9000, server);
	if (tcp_9000 < 0) {
		printf("CONNECTION ERROR! \n");
		return;
	}

	FILE *f = fopen("testing_files/rcv.JPG", "wb");
	unsigned char buff[100000];
	ssize_t r = 0;
	while ((r = receive(stack, tcp_9000, buff, 100000)) > 0) {
		printf("FILE WRITING %ld BYTES \n", r);
		if (r > 0)
			fwrite(buff, 1, r, f);
	}
	if (r < 0)
		printf("CONN RESET! \n");
	else
		printf("END OF FILE REACHED \n");

	fclose(f);
	close_socket(stack, tcp_9000);
	return;

	/*
	int tcp_9000 = open_listener(stack, SOCK_TCP, 9000);
	int udp_9001 = open_listener(stack, SOCK_UDP, 9001);
	printf("FD 9000: %d \n", tcp_9000);
	printf("FD 9001: %d \n", udp_9001);

	while (1) {
		unsigned char buff[1500];
		ipv4_address_t addr;
		uint16_t port;
		int r = receive_from(stack, udp_9001, buff, sizeof(buff), addr, &port);
		if (r >= 0) {
			struct send_request req;
			req.len = r;
			req.data = buff;
			memcpy(req.dest_ip, addr, IPV4_ADDR_LEN);
			req.dest_port = port;
			send_down(stack, udp_9001, req);
		}
	}
		*/
}

void server_app(struct stack *stack)
{
	int l = open_listener(stack, SOCK_TCP, 9000);
	int conn = accept_connection(stack, l);
	unsigned char buff[100000];

	FILE *f = fopen("testing_files/snd.JPG", "rb");
	ssize_t r;
	while ((r = fread(buff, 1, 100000, f)) != 0) {
		struct send_request req = {.data = buff, .len = r};
		send_down(stack, conn, req);
	}
	fclose(f);
	close_socket(stack, conn);

	return;
}
