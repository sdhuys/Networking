#pragma once
#include "tcp_common_types.h"
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

bool parse_tcp_options(const unsigned char *opts, int opt_len, struct tcp_options *out);
size_t tcp_options_length(struct tcp_options *opt);
size_t tcp_serialize_options(unsigned char *buf, uint8_t len, const struct tcp_options *opt);