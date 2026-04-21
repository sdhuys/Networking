#pragma once
#include "address_types.h"
#include <net/if.h>
#include <stdint.h>

struct nw_interface {
	char name[IFNAMSIZ];
	int fd;
	uint32_t ipv4_addr;   // network byte order
	uint32_t subnet_mask; // network byte order
	mac_address_t mac_addr;
	uint32_t mtu;
};

#ifdef __cplusplus
extern "C" {
#endif

void set_net_if_struct(int fd, char *if_name, struct nw_interface *n_if);
void set_stack_ipv4_addr(struct nw_interface *n_if, ipv4_address_t stack_ip_addr);
void set_net_if_struct(int fd, char *if_name, struct nw_interface *n_if);

#ifdef __cplusplus
}
#endif
