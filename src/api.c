#include "api.h"
#include "socket_manager.h"
#include "sockfd_manager.h"

int open_listener(struct stack *stack, socket_type type, uint16_t local_port)
{
	struct sockfd_manager *sockfd_mgr = stack->sock_manager->sockfd_manager;

	int fd = get_sockfd(sockfd_mgr);
	if (fd == -1)
		return -1;

	struct socket_handle h;
	int r = create_socket_handle(stack, type, local_port, &h);
	if (r < 0) {
		sockfd_free(sockfd_mgr, fd);
		return r;
	}

	assign_sock_h(sockfd_mgr, fd, h);
	return fd;
}

int receive(struct stack *stack, int sockfd, unsigned char *buff, size_t len)
{
	struct socket_handle h;
	int r = get_socket_handle(stack->sock_manager->sockfd_manager, sockfd, &h);
	if (r < 0)
		return -1; // INVALID FD
	size_t bytes_read = h.ops->read_rcv_buffer(h.sock, len, buff);
	return bytes_read;
}

int receive_from(struct stack *stack,
		 int sockfd,
		 unsigned char *buff,
		 size_t len,
		 ipv4_address addr_out,
		 uint16_t *port_out)
{
	struct socket_handle h;
	int r = get_socket_handle(stack->sock_manager->sockfd_manager, sockfd, &h);
	if (r < 0)
		return -1; // INVALID FD

	if (!h.ops->read_rcv_buffer_from)
		return -2; // INVALID SOCKET TYPE

	size_t bytes_read = h.ops->read_rcv_buffer_from(h.sock, len, buff, addr_out, port_out);
	return bytes_read;
}

int send_down(struct stack *stack, int sockfd, struct send_request req)
{
	struct socket_handle h;
	int r = get_socket_handle(stack->sock_manager->sockfd_manager, sockfd, &h);
	if (r < 0)
		return r;

	if (!h.ops->write_to_snd_buffer)
		return -2; // INVALID SOCK TYPE!

	bool success = h.ops->write_to_snd_buffer(stack, h.sock, req);
	return success ? 0 : WRITE_ERROR;
}

int close_socket(struct stack *stack, int sockfd)
{
	struct socket_handle h;
	int r = get_socket_handle(stack->sock_manager->sockfd_manager, sockfd, &h);
	if (r < 0)
		return r;

	h.ops->close(stack, h.sock);
	h.ops->release(h.sock); // not for tcp??

	sockfd_free(stack->sock_manager->sockfd_manager, sockfd);
	return 0;
}