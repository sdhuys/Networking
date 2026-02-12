#include "stack_constructor.h"

struct stack_t construct_stack(int fd, char *if_name)
{
	struct nw_layer_t *interface = malloc(sizeof(struct nw_layer_t));
	struct nw_layer_t *eth = malloc(sizeof(struct nw_layer_t));
	struct nw_layer_t *arp = malloc(sizeof(struct nw_layer_t));
	struct nw_layer_t *ip = malloc(sizeof(struct nw_layer_t));
	struct nw_layer_t *icmp = malloc(sizeof(struct nw_layer_t));
	struct nw_layer_t *udp = malloc(sizeof(struct nw_layer_t));
	struct nw_layer_t *tcp = malloc(sizeof(struct nw_layer_t));

	int wake_fd = eventfd(0, EFD_NONBLOCK);
	struct timer_min_heap_t *timers_heap = create_timers_min_heap(wake_fd);

	interface->name = if_name;
	interface->send_down = &write_to_interface;
	interface->rcv_up = &send_up_to_ethernet;
	interface->ups_count = 1;
	interface->ups = malloc(interface->ups_count * sizeof(struct nw_layer_t *));
	interface->ups[0] = eth;
	interface->downs = NULL;
	interface->downs_count = 0;
	struct interface_context_t *nw_if_context = malloc(sizeof(struct interface_context_t));
	nw_if_context->if_amount = 1;
	struct nw_interface_t *nw_if = malloc(sizeof(struct nw_interface_t));
	set_net_if_struct(fd, if_name, nw_if);
	nw_if_context->interfaces = nw_if;
	nw_if_context->timers_heap = timers_heap;
	nw_if_context->wake_fd = wake_fd;
	interface->context = nw_if_context;

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

	struct socket_manager_t *socket_manager = malloc(sizeof(struct socket_manager_t));
	socket_manager->receive_up_sock_q = malloc(sizeof(struct socket_h_q_t));
	socket_manager->send_down_sock_q = malloc(sizeof(struct socket_h_q_t));
	socket_manager->receive_up_sock_q->head = NULL;
	socket_manager->receive_up_sock_q->tail = NULL;
	socket_manager->receive_up_sock_q->len = 0;
	pthread_cond_init(&socket_manager->receive_up_sock_q->cond, NULL);
	pthread_mutex_init(&socket_manager->receive_up_sock_q->lock, NULL);
	socket_manager->send_down_sock_q->head = NULL;
	socket_manager->send_down_sock_q->tail = NULL;
	socket_manager->send_down_sock_q->len = 0;
	pthread_cond_init(&socket_manager->send_down_sock_q->cond, NULL);
	pthread_mutex_init(&socket_manager->send_down_sock_q->lock, NULL);
	socket_manager->udp_ipv4_sckt_htable = create_udp_ipv4_sckt_htable();
	socket_manager->tcp_ipv4_listener_htable = create_tcp_ipv4_listener_htable();
	socket_manager->tcp_ipv4_conn_htable = create_tcp_ipv4_conn_htable();

	udp->name = UDP_NAME;
	udp->send_down = &send_udp_down;
	udp->rcv_up = &receive_udp_up;
	udp->ups = NULL;
	udp->ups_count = 0;
	udp->downs_count = 1;
	udp->downs = malloc(udp->downs_count * sizeof(struct nw_layer_t *));
	udp->downs[0] = ip;
	struct udp_context_t *udp_context = malloc(sizeof(struct udp_context_t));
	memcpy(udp_context->stack_ipv4_addr, stack_ipv4_addr, IPV4_ADDR_LEN);
	udp_context->sock_manager = socket_manager;
	udp->context = udp_context;

	tcp->name = TCP_NAME;
	tcp->send_down = &send_tcp_down;
	tcp->rcv_up = &receive_tcp_up;
	tcp->ups = NULL;
	tcp->ups_count = 0;
	tcp->downs_count = 1;
	tcp->downs = malloc(tcp->downs_count * sizeof(struct nw_layer_t *));
	tcp->downs[0] = ip;
	struct tcp_context_t *tcp_context = malloc(sizeof(struct tcp_context_t));
	memcpy(tcp_context->stack_ipv4_addr, stack_ipv4_addr, IPV4_ADDR_LEN);
	tcp_context->timers = timers_heap;
	tcp_context->socket_manager = socket_manager;
	tcp->context = tcp_context;

	struct stack_t stack = {.if_layer = interface,
				.tcp_layer = tcp,
				.udp_layer = udp,
				.sock_manager = socket_manager};
	memcpy(stack.local_address, stack_ipv4_addr, IPV4_ADDR_LEN);
	return stack;
}

struct udp_ipv4_sckt_htable_t *create_udp_ipv4_sckt_htable()
{
	struct udp_ipv4_sckt_htable_t *udp_htable = malloc(sizeof(struct udp_ipv4_sckt_htable_t));
	udp_htable->buckets_amount = UDP_SCKT_HTBL_SIZE;
	pthread_mutex_t *bckt_locks = malloc(sizeof(pthread_mutex_t) * UDP_SCKT_HTBL_SIZE);
	for (int i = 0; i < UDP_SCKT_HTBL_SIZE; i++)
		pthread_mutex_init(&bckt_locks[i], NULL);
	udp_htable->bucket_locks = bckt_locks;
	struct udp_ipv4_sckt_htable_node_t **buckets =
	    calloc(UDP_SCKT_HTBL_SIZE, sizeof(struct udp_ipv4_sckt_htable_node_t));
	udp_htable->buckets = buckets;
	return udp_htable;
}

struct tcp_ipv4_listener_htable_t *create_tcp_ipv4_listener_htable()
{
	struct tcp_ipv4_listener_htable_t *tcp_lstnr_htable =
	    malloc(sizeof(struct tcp_ipv4_listener_htable_t));
	tcp_lstnr_htable->buckets_amount = TCP_LISTNR_HTBL_SIZE;
	pthread_mutex_t *bckt_locks = malloc(sizeof(pthread_mutex_t) * TCP_LISTNR_HTBL_SIZE);
	for (int i = 0; i < TCP_LISTNR_HTBL_SIZE; i++)
		pthread_mutex_init(&bckt_locks[i], NULL);
	tcp_lstnr_htable->bucket_locks = bckt_locks;
	struct tcp_ipv4_listener_node_t **buckets =
	    calloc(TCP_LISTNR_HTBL_SIZE, sizeof(struct tcp_ipv4_listener_node_t));
	tcp_lstnr_htable->buckets = buckets;
	return tcp_lstnr_htable;
}

struct tcp_ipv4_conn_htable_t *create_tcp_ipv4_conn_htable()
{
	return NULL;
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