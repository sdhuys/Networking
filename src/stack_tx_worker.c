#include "stack_tx_worker.h"
#include <stdio.h>

void *stack_transmission_loop(void *arg)
{
	struct stack_t *stack = (struct stack_t *)arg;
	struct socket_manager_t *mgr = stack->sock_manager;
	struct socket_h_q_t *q = mgr->send_down_sock_q;
	while (1) {
		pthread_mutex_lock(&q->lock);
		while (q->len == 0) {
			pthread_cond_wait(&q->cond, &q->lock);
		}
		pthread_mutex_unlock(&q->lock);
		printf("STACK TRANSMISSION WAKEN UP \n \n");
		while (1) {
			struct socket_handle_t h = dequeue_writable_socket(mgr);

			if (!h.sock)
				break;

			struct pkt_t *pkt = NULL;
			pkt_result res;

			// --- TYPE-SPECIFIC DISPATCH ---
			if (h.type == SOCK_UDP) {
				struct udp_ipv4_socket_t *udp_sock =
				    (struct udp_ipv4_socket_t *)h.sock;

				// Drain UDP ring buffer
				while ((pkt = read_buffer(udp_sock->snd_buffer)) != NULL) {

					printf("DEBUG: read_buffer returned packet %p, pool_index: "
					       "%d\n",
					       (void *)pkt,
					       pkt->pool_index);

					res = stack->udp_layer->send_down(stack->udp_layer, pkt);
				}

			} else if (h.type == SOCK_TCP) {
				struct tcp_ipv4_socket_t *tcp_sock =
				    (struct tcp_ipv4_socket_t *)h.sock;

				while ((pkt = read_buffer(&tcp_sock->snd_buffer)) != NULL) {
					res = stack->tcp_layer->send_down(stack->tcp_layer, pkt);
				}
			}
			printf("STACK WORKER RESULT: %d \n", res);
			release_socket_from_queue(h, false);
		}
	}
	return NULL;
}