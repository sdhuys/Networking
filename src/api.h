#pragma once
#include "socket_types.h"
#include "types.h"
#include <stddef.h>
#include <stdint.h>

struct stack;

int open_listener(struct stack *stack, socket_type type, uint16_t local_port);
int receive(struct stack *stack, int sockfd, unsigned char *buff, size_t len);
int receive_from(struct stack *stack,
		 int sockfd,
		 unsigned char *buff,
		 size_t len,
		 ipv4_address addr_out,
		 uint16_t *port_out);
int send_down(struct stack *stack, int sockfd, struct send_request req);
int close_socket(struct stack *stack, int sockfd);
