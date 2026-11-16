#pragma once
#include "address_types.h"

#ifdef __cplusplus
extern "C" {
#endif

int tap_setup(char *name, const ipv4_address_t tap_ip, const uint32_t mtu);

#ifdef __cplusplus
}
#endif
