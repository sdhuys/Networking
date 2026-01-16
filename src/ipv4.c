#include "layer.h"

// TAP's IPV4 set to 192.168.100.1 by set_ipv4_addr()
// subnet mask defaulted to 255.255.255.0
// dummy must be on same subnet
#define DUMMY_IPV4 (unsigned char[4]){192, 168, 100, 2}
