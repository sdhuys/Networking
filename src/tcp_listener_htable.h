#pragma once
#include "types.h"

struct tcp_ipv4_listener_node_t
{
	struct tcp_ipv4_listener_t *listener;
	struct tcp_ipv4_listener_t *next;
};

struct tcp_ipv_listener_htable_t
{
    struct tcp_ipv4_listener_node_t **buckets;
    uint8_t buckets_amount;
    pthread_mutex_t *bucket_locks; // lock per bucket
};