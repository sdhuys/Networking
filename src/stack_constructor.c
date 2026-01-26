#include "stack_constructor.h"

struct nw_layer_t *construct_stack(int fd, char *if_name)
{
	struct nw_layer_t *interface = malloc(sizeof(struct nw_layer_t));
	struct nw_layer_t *eth = malloc(sizeof(struct nw_layer_t));
	struct nw_layer_t *arp = malloc(sizeof(struct nw_layer_t));
	struct nw_layer_t *ip = malloc(sizeof(struct nw_layer_t));
	struct nw_layer_t *icmp = malloc(sizeof(struct nw_layer_t));
	struct nw_layer_t *udp = malloc(sizeof(struct nw_layer_t));
	struct nw_layer_t *tcp = malloc(sizeof(struct nw_layer_t));

	static struct socket_manager_t socket_manager;

	interface->name = if_name;
	interface->send_down = &write_to_interface;
	interface->rcv_up = &send_up_to_ethernet;
	interface->ups_count = 1;
	interface->ups = malloc(interface->ups_count * sizeof(struct nw_layer_t *));
	interface->ups[0] = eth;
	interface->downs = NULL;
	interface->downs_count = 0;
	struct nw_interface_t *nw_if = malloc(sizeof(struct nw_interface_t));
	set_net_if_struct(fd, if_name, nw_if);
	interface->context = nw_if;

	// assign stack mac address and ip address on same subnet as interface
	static unsigned char stack_mac_addr[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
	static unsigned char stack_ipv4_addr[4];
	void set_net_if_struct(int fd, char *if_name, struct nw_interface_t *n_if);
	set_stack_ipv4_addr(nw_if, stack_ipv4_addr);

	eth->name = ETH_NAME;
	eth->send_down = &send_frame_down;
	eth->rcv_up = &receive_frame_up;
	eth->ups_count = 2;
	eth->downs_count = 1;
	eth->ups = malloc(eth->ups_count * sizeof(struct nw_layer_t *));
	eth->ups[0] = arp;
	eth->ups[1] = ip;
	eth->downs = malloc(eth->downs_count * sizeof(struct nw_layer_t *));
	eth->downs[0] = interface;
	struct ethernet_context_t *eth_context = malloc(sizeof(struct ethernet_context_t));
	memcpy(eth_context->mac_addr, stack_mac_addr, MAC_ADDR_LEN);
	eth->context = eth_context;

	arp->name = ARP_NAME;
	arp->send_down = &send_arp_down;
	arp->rcv_up = &receive_arp_up;
	arp->ups = NULL;
	arp->ups_count = 0;
	arp->downs_count = 1;
	arp->downs = malloc(arp->downs_count * sizeof(struct nw_layer_t *));
	arp->downs[0] = eth;
	struct arp_context_t *arp_ctx = malloc(sizeof(struct arp_context_t));
	struct arp_table_t *arp_table_head = malloc(sizeof(struct arp_table_t));
	arp_ctx->arp_table = arp_table_head;
	memcpy(arp_ctx->ipv4_addr, stack_ipv4_addr, IPV4_ADDR_LEN);
	memcpy(arp_ctx->mac_addr, stack_mac_addr, MAC_ADDR_LEN);
	arp->context = arp_ctx;

	ip->name = IPV4_NAME;
	ip->send_down = &send_ipv4_down;
	ip->rcv_up = &receive_ipv4_up;
	ip->ups_count = 3;
	ip->downs_count = 1;
	ip->ups = malloc(ip->ups_count * sizeof(struct nw_layer_t *));
	ip->ups[0] = icmp;
	ip->ups[1] = udp;
	ip->ups[2] = tcp;
	ip->downs = malloc(ip->downs_count * sizeof(struct nw_layer_t *));
	ip->downs[0] = eth;
	struct ipv4_context_t *ipv4_context = malloc(sizeof(struct ipv4_context_t));
	ipv4_context->arp_layer = arp;
	ipv4_context->routing_table = create_routing_table(nw_if);
	ipv4_context->routes_amount = get_init_routes_amount();
	memcpy(ipv4_context->stack_ipv4_addr, stack_ipv4_addr, IPV4_ADDR_LEN);
	ipv4_context->nw_if = nw_if;
	ip->context = ipv4_context;

	icmp->name = ICMP_NAME;
	icmp->send_down = &send_icmp_down;
	icmp->rcv_up = &receive_icmp_up;
	icmp->ups = NULL;
	icmp->ups_count = 0;
	icmp->downs_count = 1;
	icmp->downs = malloc(icmp->downs_count * sizeof(struct nw_layer_t *));
	icmp->downs[0] = ip;

	udp->name = UDP_NAME;
	udp->send_down = &send_udp_down;
	udp->rcv_up = &receive_udp_up;
	udp->ups = NULL;
	udp->ups_count = 0;
	udp->downs_count = 1;
	udp->downs = malloc(udp->downs_count * sizeof(struct nw_layer_t *));
	udp->downs[0] = ip;

	tcp->name = TCP_NAME;
	tcp->send_down = &send_tcp_down;
	tcp->rcv_up = &receive_tcp_up;
	tcp->ups = NULL;
	tcp->ups_count = 0;
	tcp->downs_count = 1;
	tcp->downs = malloc(tcp->downs_count * sizeof(struct nw_layer_t *));
	tcp->downs[0] = ip;

	return interface;
}

void set_net_if_struct(int fd, char *if_name, struct nw_interface_t *n_if)
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
void set_stack_ipv4_addr(struct nw_interface_t *n_if, ipv4_address stack_ip_addr)
{
	uint32_t ip = ntohl(n_if->ipv4_addr);
	uint32_t mask = ntohl(n_if->subnet_mask);

	uint32_t network = ip & mask;

	uint32_t stack_ip = htonl(network | 2);
	memcpy(stack_ip_addr, &stack_ip, IPV4_ADDR_LEN);
}