#include "stack_tx_worker.h"
#include <stdio.h>

void *stack_transmission_loop(void *arg)
{
	struct stack *stack = (struct stack *)arg;
	struct socket_manager *mgr = stack->sock_manager;
	struct socket_h_q *q = mgr->send_down_sock_q;
	while (1) {
		pthread_mutex_lock(&q->lock);
		while (q->len == 0) {
			pthread_cond_wait(&q->cond, &q->lock);
		}
		pthread_mutex_unlock(&q->lock);
		while (1) {
			struct socket_handle h = dequeue_sock_snd_down_q(mgr);
			if (!h.sock)
				break;

			struct pkt *pkt;
			pkt_result res;

			while ((pkt = h.ops->next_snd_pkt(h.sock)) != NULL) {
				res = h.ops->send_pkt(stack, pkt);
			}
			printf("WORKER RESULT: %d", res);
			release_socket_from_queue(h);
		}
	}
	return NULL;
}