#pragma once
#include <stdlib.h>
#include "arp.h"
#include "ethernet.h"
#include "icmp.h"
#include "ipv4.h"
#include "routing_table.h"
#include "tap.h"
#include "tcp.h"
#include "udp.h"

#ifdef __cplusplus
extern "C"
{
#endif

struct nw_layer *construct_stack(int fd);

#ifdef __cplusplus
}
#endif
