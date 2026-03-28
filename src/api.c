#include "api.h"
#include "socket_manager.h"
#include "sockfd_manager.h"
#include "tcp_common_types.h"
#include "tcp_conn_htable.h"

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
		 ipv4_address_t addr_out,
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
	h.ops->release(h.sock);

	sockfd_free(stack->sock_manager->sockfd_manager, sockfd);
	return 0;
}

int accept_connection(struct stack *stack, int sockfd)
{
	struct sockfd_manager *sockfd_mgr = stack->sock_manager->sockfd_manager;
	struct socket_handle lis_h;
	int r = get_socket_handle(sockfd_mgr, sockfd, &lis_h);
	if (r < 0)
		return r;

	if (!lis_h.ops->accept)
		return -2; // INVALID SOCKET TYPE

	struct tcp_ipv4_conn *conn = lis_h.ops->accept(lis_h.sock);
	retain_tcp_conn(conn);

	struct socket_handle conn_h = create_conn_sock_h(conn);
	int fd = get_sockfd(sockfd_mgr);
	if (fd == -1)
		return -1; // MAX FD REACHED

	assign_sock_h(sockfd_mgr, fd, conn_h);
	return fd;
}

int tcp_connect(struct stack *stack,
		uint16_t local_port,
		uint16_t extern_port,
		ipv4_address_t extern_addr)
{
	struct tcp_ipv4_conn_htable *htable = stack->sock_manager->tcp_ipv4_conn_htable;
	struct tcp_ipv4_conn_htable *tw_htable =
	    stack->sock_manager->tcp_ipv4_conn_time_wait_htable;
	struct tcp_conn_id id = {.extern_port = extern_port, .loc_port = local_port};
	memcpy(id.extern_addr, extern_addr, IPV4_ADDR_LEN);
	memcpy(id.loc_addr, stack->local_address, IPV4_ADDR_LEN);

	if (query_tcp_conn_hashtable(htable, id) || query_tcp_conn_hashtable(tw_htable, id))
		return -1; // CONNECTION ALREADY IN USE

	struct tcp_ipv4_conn *conn = create_init_tcp_connection(&id, stack->tcp_layer);
	retain_tcp_conn(conn);
	client_init_tcp_connection(conn);
	add_to_tcp_conn_hashtable(htable, conn);
	tcp_transition_to_state(conn, SYN_SENT);
	tcp_syn_to_snd_buff(conn);
	tcp_lock_conn(conn);

	while (conn->state != ESTABLISHED) {
		if (conn->state == CLOSED)
			return -2; // CONNECTION FAILED
		pthread_cond_wait(&conn->estblshd_cond, &conn->lock);
	}
	tcp_unlock_conn(conn);
	struct socket_handle conn_h = create_conn_sock_h(conn);
	struct sockfd_manager *sockfd_mgr = stack->sock_manager->sockfd_manager;
	int fd = get_sockfd(sockfd_mgr);
	if (fd == -1)
		return -1; // MAX FD REACHED

	assign_sock_h(sockfd_mgr, fd, conn_h);
	return fd;
}

int tcp_end_send(struct stack *stack, int sockfd)
{
	struct socket_handle h;
	int r = get_socket_handle(stack->sock_manager->sockfd_manager, sockfd, &h);
	if (r < 0)
		return r;

	if (!h.ops->end_snd)
		return -2; // INVALID SOCKET TYPE
	h.ops->end_snd(stack, h.sock);
	return 0;
}
