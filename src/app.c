#include "app.h"
#include "socket_manager.h"
#include "types.h"
#include "udp_hashtable.h"
#include "udp_socket.h"
#include <stdio.h>
#include <unistd.h>

void start_app(struct socket_manager_t *socket_manager)
{
	app_socket_open(socket_manager, SOCK_UDP, 9000);

	struct socket_h_q_t *read_queue = socket_manager->receive_up_sock_q;
	pthread_mutex_lock(&read_queue->lock);
	while (1) {
		while (read_queue->len == 0) {
			pthread_cond_wait(&read_queue->cond, &read_queue->lock);
		}
		pthread_mutex_unlock(&read_queue->lock);

		while (1) {
			struct socket_handle_t socket = dequeue_readable_socket(socket_manager);
			if (!socket.sock)
				break;

			struct pkt_t *pkt;
			while ((pkt = app_socket_receive(socket)) != NULL) {
				unsigned char *buffer = malloc(pkt->len);

				memcpy(buffer, (pkt->data + pkt->offset), pkt->len);
				struct send_request_t req = {
				    .data = buffer, .dest_port = pkt->src_port, .len = pkt->len};
				memcpy(req.dest_ip, pkt->src_ip, IPV4_ADDR_LEN);
				app_socket_send(socket, req);
				app_socket_release_packet(pkt);
			}
			release_socket_from_queue(socket, true);
		}
	}
}

struct socket_handle_t app_socket_open(struct socket_manager_t *socket_manager,
				       socket_type_t type,
				       uint16_t local_port)
{
	struct socket_handle_t handle = {0};

	switch (type) {
	case SOCK_UDP:
		struct udp_ipv4_socket_t *sock = create_udp_socket(local_port);
		if (!sock)
			return handle;
		sock->mgr = socket_manager;
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

pkt_result app_socket_send(struct socket_handle_t sock, struct send_request_t req)
{
	if (!sock.sock || !sock.ops || !sock.ops->write_to_snd_buffer)
		return WRITE_ERROR;

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
