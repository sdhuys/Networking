#include "app.h"
#include <stdio.h>

void start_app(struct stack *stack)
{
	int udp_9000 = open_listener(stack, SOCK_TCP, 9000);
	int udp_9001 = open_listener(stack, SOCK_TCP, 9001);
	printf("FD 9000: %d \n", udp_9000);
	printf("FD 9001: %d \n", udp_9001);
	printf("CLOSE SOCKET: %d \n", close_socket(stack, udp_9001));
	while (1) {
		unsigned char buff[1500];
		ipv4_address_t addr;
		uint16_t port;
		int r = receive_from(stack, udp_9000, buff, sizeof(buff), addr, &port);
		if (r >= 0) {
			struct send_request req;
			req.len = r;
			req.data = buff;
			memcpy(req.dest_ip, addr, IPV4_ADDR_LEN);
			req.dest_port = port;
			send_down(stack, udp_9000, req);
		}
	}
}
