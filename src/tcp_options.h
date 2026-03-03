#pragma once
#include "tcp_common_types.h"
#include "timer.h"
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define TCP_OP_TS_LEN 12
#define TCP_HEADER_MAX_SACK 4

bool parse_tcp_options(const unsigned char *opts, int opt_len, struct tcp_options *out);
size_t calc_tcp_options_len(struct tcp_options *opt);
size_t tcp_serialize_options(unsigned char *buf, const struct tcp_options *opt);