#include "app.h"
#include <stdio.h>

void start_app(struct stack *stack)
{
	ipv4_address_t gdns = {8, 8, 8, 8};
	int g_dns = tcp_connect(stack, 1234, 53, gdns);
	printf("\n\nGDNS FD: %i \n\n", g_dns);
	printf("CLOSE: %i\n", close_socket(stack, g_dns));
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
}
