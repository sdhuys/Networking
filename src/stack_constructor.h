#pragma once
#include <stdlib.h>
#include "arp.h"
#include "ethernet.h"
#include "ipv4.h"
#include "icmp.h"
#include "tap.h"
#include "tcp.h"
#include "udp.h"

struct nw_layer *construct_stack();