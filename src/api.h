#pragma once
#include "socket_types.h"
#include "types.h"
#include <stddef.h>
#include <stdint.h>

struct stack_t;

int open_listener(struct stack_t *stack, socket_type_t type, uint16_t local_port);
int receive(struct stack_t *stack, int sockfd, unsigned char *buff, size_t len);
int receive_from(struct stack_t *stack,
		 int sockfd,
		 unsigned char *buff,
		 size_t len,
		 ipv4_address addr_out,
		 uint16_t *port_out);
int send_down(struct stack_t *stack, int sockfd, struct send_request_t req);
int close_socket(struct stack_t *stack, int sockfd);
