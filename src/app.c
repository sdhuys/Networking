#include "socket_manager.h"
#include "types.h"
#include "udp_hashtable.h"
#include "udp_socket.h"

void start_app(struct socket_manager_t *socket_manager)
{
	// OPEN SOCKETS
	// LOOP READING socket_manager->receive_up_sock_q
	// echo data back to socket_manager->send_down_sock_q
}

struct socket_handle_t
app_socket_open(struct socket_manager_t *socket_manager, socket_type_t type, uint16_t local_port)
{
	struct socket_handle_t handle = {0};

	switch (type) {
	case SOCK_UDP:
		struct udp_ipv4_socket_t *sock = create_udp_socket(local_port);
		if (!sock)
			return handle;

		handle.sock = sock;
		handle.type = SOCK_UDP;
		handle.ops = &udp_socket_ops;
		handle.ops->retain(sock); // app owns initial reference

		add_to_hashtable(socket_manager->udp_ipv4_sckt_htable, sock); // second ref

		break;

	case SOCK_TCP:

		// ADD TO TCP SOCKET HASHTABLE
		break;
	}

	return handle;
}

void app_socket_close(struct socket_manager_t *socket_manager, struct socket_handle_t socket_h)
{
	if (!socket_h.sock || !socket_h.ops)
		return;
	if (socket_h.type == SOCK_UDP)
		remove_from_udp_hashtable(socket_manager->udp_ipv4_sckt_htable, socket_h.sock);
	else if (socket_h.type == SOCK_TCP)
		// remove_from_tcp_hashtable(socket_manager->tcp_ipv4_sckt_htable, socket_h.sock);

		socket_h.ops->release(socket_h.sock);
}

pkt_result app_socket_send(struct socket_handle_t sock, unsigned char *data, size_t len)
{
	if (!sock.sock || !sock.ops || !sock.ops->write_to_snd_buffer)
		return WRITE_ERROR;

	struct send_request_t req;
	req.data = data;
	req.len = len;

	bool success = sock.ops->write_to_snd_buffer(sock.sock, req);
	return success ? SENT : WRITE_ERROR;
}

struct pkt_t *app_socket_receive(struct socket_handle_t sock)
{
	if (!sock.sock || !sock.ops || !sock.ops->read_rcv_buffer)
		return NULL;

	return sock.ops->read_rcv_buffer(sock.sock);
}

void app_socket_release_packet(struct pkt_t *pkt)
{
	if (!pkt)
		return;
	release_pkt(pkt);
}
