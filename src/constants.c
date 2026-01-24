#include "types.h"

const unsigned char IPV4_BROADCAST_MAC[MAC_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
// TAP's IPV4 set to 192.168.100.1 by set_ipv4_addr()
// subnet mask defaulted to 255.255.255.0
// dummy must be on same subnet
const unsigned char DUMMY_IPV4[4] = {192, 168, 100, 2};
const unsigned char DUMMY_MAC_ADDR[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
