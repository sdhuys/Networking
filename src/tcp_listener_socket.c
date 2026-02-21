#include "tcp_listener_socket.h"
#include "time.h"

#define TCP_LSTNR_HALF_OPENS_BCKT_COUNT 1024
#define TCP_LSTNR_HALF_OPENS_LIMIT 256

static const uint16_t mss_enc_table[8] = {
    TCP_MSS_DEFAULT_FALLBACK, 872, 1064, 1192, 1320, TCP_MSS_TS, TCP_MSS_MAX};

const struct socket_ops tcp_listener_ops = {.is_snd_queued = NULL,
					    .set_snd_queued = NULL,
					    .retain = tcp_retain_listener,
					    .release = tcp_release_listener,
					    .write_to_snd_buffer = NULL,
					    .read_rcv_buffer = NULL,
					    .unlock = tcp_unlock_listener,
					    .lock = tcp_lock_listener,
					    .next_snd_pkt = NULL,
					    .send_pkt = NULL,
					    .close = tcp_close_listener};

pkt_result process_incoming_syn(struct tcp_ipv4_listener *listener,
				struct tcp_segment seg_in,
				struct pkt *p)
{
	uint32_t iss;
	uint32_t ack = seg_in.header->seq_num + seg_len(seg_in);
	bool use_syn_cookie = listener->half_open_count >= listener->half_open_limit;
	if (use_syn_cookie) {
		iss = generate_syn_cookie_iss(listener, seg_in, p);
		// SEND SYN ACK
		return NOT_IMPLEMENTED_YET;
	}

	else {
		iss = generate_random_iss();
		struct tcp_ipv4_conn *conn = create_ipv4_connection(seg_in, iss);
		if (conn == NULL)
			return TCP_CONN_CREATION_ERROR;
		// add connection to listener's half-open htable
		// send SYN ACK
	}
	return NOT_IMPLEMENTED_YET;
}

uint32_t generate_syn_cookie_iss(struct tcp_ipv4_listener *listener,
				 struct tcp_segment seg,
				 struct pkt *p)
{
	uint32_t mss = seg.options.mss_present ? seg.options.mss : TCP_MSS_DEFAULT_FALLBACK;
	unsigned char data[(2 * sizeof(ipv4_address)) + (2 * sizeof(uint16_t))];

	memcpy(data, listener->local_addr, IPV4_ADDR_LEN);
	memcpy(data + IPV4_ADDR_LEN, &listener->local_port, sizeof(uint16_t));
	memcpy(data + IPV4_ADDR_LEN + sizeof(uint16_t), &p->src_ip, IPV4_ADDR_LEN);
	memcpy(data + IPV4_ADDR_LEN + sizeof(uint16_t) + IPV4_ADDR_LEN,
	       &seg.header->src_port,
	       sizeof(uint16_t));
	uint64_t time = now_s() >> 6;

	uint32_t hash = hash_syncookie(data, sizeof(*data), time) & ((1 << 24) - 1);

	uint32_t iss = time % 32;
	iss = (iss << 3) | mss_encode(mss);
	iss = (iss << 24) | hash;
	return iss;
}

uint8_t mss_encode(uint16_t mss)
{
	for (int i = 7; i >= 0; i--) {
		if (mss >= mss_enc_table[i])
			return i;
	}
	return 0;
}

uint16_t mss_decode(uint8_t enc)
{
	return mss_enc_table[enc & 7];
}

pkt_result syn_cookie_check_ack(struct tcp_ipv4_listener *listener, struct tcp_segment seg)
{
	return NOT_IMPLEMENTED_YET;
}

pkt_result half_open_check_ack(struct tcp_segment seg,
			       struct tcp_ipv4_conn *half_open,
			       struct tcp_ipv4_listener *lstnr)
{
	return NOT_IMPLEMENTED_YET;
}

struct tcp_ipv4_listener *create_tcp_listener(uint16_t port, struct stack *stack)
{
	struct tcp_ipv4_listener *listener = malloc(sizeof(struct tcp_ipv4_listener));
	if (listener == NULL)
		return NULL;

	listener->ready_q = create_ready_q();
	if (!listener->ready_q) {
		free(listener);
		return NULL;
	}
	listener->half_opens = create_tcp_ipv4_conn_htable(TCP_LSTNR_HALF_OPENS_BCKT_COUNT);
	listener->half_open_limit = TCP_LSTNR_HALF_OPENS_LIMIT;
	listener->local_port = port;
	memcpy(listener->local_addr, stack->local_address, IPV4_ADDR_LEN);
	listener->state = TCP_LIS_LISTEN;
	pthread_mutex_init(&listener->lock, NULL);
	return listener;
}

void retain_tcp_listener(struct tcp_ipv4_listener *listener)
{
	pthread_mutex_lock(&(listener->lock));
	listener->ref_count++;
	pthread_mutex_unlock(&(listener->lock));
}

void release_tcp_listener(struct tcp_ipv4_listener *listener)
{
	bool should_destroy = false;
	pthread_mutex_lock(&(listener->lock));

	listener->ref_count--;
	if (listener->ref_count <= 0)
		should_destroy = true;

	pthread_mutex_unlock(&(listener->lock));
	if (should_destroy)
		destroy_tcp_listener(listener);
}

void destroy_tcp_listener(struct tcp_ipv4_listener *listener)
{
	pthread_mutex_lock(&listener->lock);
	listener->state = TCP_LIS_CLOSED;
	destroy_ready_q(listener->ready_q);
	pthread_mutex_unlock(&listener->lock);
	pthread_mutex_destroy(&listener->lock);
	free(listener);
}

void tcp_release_listener(void *s)
{
	struct tcp_ipv4_listener *listener = (struct tcp_ipv4_listener *)s;
	release_tcp_listener(listener);
}

void tcp_retain_listener(void *s)
{
	struct tcp_ipv4_listener *listener = (struct tcp_ipv4_listener *)s;
	retain_tcp_listener(listener);
}

void tcp_close_listener(struct stack *stack, void *s)
{
	struct tcp_ipv4_listener *listener = (struct tcp_ipv4_listener *)s;
	remove_from_tcp_listener_hashtable(stack->sock_manager->tcp_ipv4_listener_htable, listener);
}

void tcp_lock_listener(void *s)
{
	struct tcp_ipv4_listener *listener = (struct tcp_ipv4_listener *)s;
	pthread_mutex_lock(&listener->lock);
}

void tcp_unlock_listener(void *s)
{
	struct tcp_ipv4_listener *listener = (struct tcp_ipv4_listener *)s;
	pthread_mutex_unlock(&listener->lock);
}

struct tcp_ipv4_conn_q *create_ready_q()
{
	struct tcp_ipv4_conn_q *q = malloc(sizeof(struct tcp_ipv4_conn_q));
	if (!q)
		return NULL;

	q->len = 0;
	q->head = NULL;
	q->tail = NULL;
	return q;
}

void destroy_ready_q(struct tcp_ipv4_conn_q *q)
{
	struct tcp_ipv4_conn_q_node *node = q->head;
	while (node) {
		struct tcp_ipv4_conn_q_node *next = node->next;
		destroy_tcp_conn(node->conn);
		free(node);
		node = next;
	}
	free(q);
}
