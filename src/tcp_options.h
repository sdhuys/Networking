#pragma once
#include "tcp_common_types.h"
#include <stdbool.h>
#include <stdint.h>

bool parse_tcp_options(const unsigned char *opts, int opt_len, struct tcp_options *out);