#include "nw_interface.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

void set_net_if_struct(int fd, char *if_name, struct nw_interface *n_if)
{
	int sock;
	struct ifreq ifr;

	n_if->fd = fd;
	strcpy(n_if->name, if_name);

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0) {
		perror("socket");
		return;
	}

	strncpy(ifr.ifr_name, if_name, IFNAMSIZ);

	if (ioctl(sock, SIOCGIFADDR, &ifr) == 0)
		n_if->ipv4_addr = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;
	else
		perror("SIOCGIFADDR");

	if (ioctl(sock, SIOCGIFNETMASK, &ifr) == 0)
		n_if->subnet_mask = ((struct sockaddr_in *)&ifr.ifr_netmask)->sin_addr.s_addr;
	else
		perror("SIOCGIFNETMASK");

	if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0)
		memcpy(n_if->mac_addr, ifr.ifr_hwaddr.sa_data, 6);
	else
		perror("SIOCGIFHWADDR");

	if (ioctl(sock, SIOCGIFMTU, &ifr) == 0)
		n_if->mtu = ifr.ifr_mtu;
	else
		perror("SIOCGIFMTU");

	close(sock);
}

// Sets stack ip address on same subnet as the interface, with host bits set to 2
// after set_ipv4_addr() call => interface at 192.168.100.1/24
// after this call => stack at 192.168.100.2/24
void set_stack_ipv4_addr(struct nw_interface *n_if, ipv4_address_t stack_ip_addr)
{
	uint32_t ip = ntohl(n_if->ipv4_addr);
	uint32_t mask = ntohl(n_if->subnet_mask);

	uint32_t network = ip & mask;

	uint32_t stack_ip = htonl(network | 2);
	memcpy(stack_ip_addr, &stack_ip, IPV4_ADDR_LEN);
}
