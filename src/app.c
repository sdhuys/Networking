#include "app.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void client_app(struct stack *stack)
{
	ipv4_address_t server = {192, 168, 100, 2};
	int tcp_9000 = tcp_connect(stack, 1234, 9000, server);
	if (tcp_9000 < 0) {
		printf("CONNECTION ERROR! \n");
		return;
	}
	tcp_end_send(stack, tcp_9000);
	FILE *f = fopen("testing_files/rcv.JPG", "wb");
	unsigned char buff[100000];
	ssize_t r = 0;
	while ((r = receive(stack, tcp_9000, buff, 100000)) > 0) {
		printf("FILE WRITING %ld BYTES \n", r);
		if (r > 0)
			fwrite(buff, 1, r, f);
		sleep(2); // CAUSE ZERO WINDOWS
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
	unsigned char buff[0x80000];
	FILE *f = fopen("testing_files/snd.JPG", "rb");
	ssize_t r;
	while ((r = fread(buff, 1, 0x80000, f)) > 0) {
		size_t count = 0;

		do {
			struct send_request req = {.data = buff + count, .len = r - count};
			int sent_down = send_down(stack, conn, &req);
			count += sent_down;

		} while (count < (size_t)r);
	}
	if (r != 0)
		printf("read error %lu", r);

	fclose(f);
	close_socket(stack, conn);
	return;
}
