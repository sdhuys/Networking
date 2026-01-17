#include "stack_constructor.h"

// TAP's IPV4 set to 192.168.100.1 by set_ipv4_addr()
// subnet mask defaulted to 255.255.255.0
// dummy must be on same subnet

static unsigned char DUMMY_IPV4[4] = {192, 168, 100, 2};
static unsigned char DUMMY_MAC_ADDR[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};

struct nw_layer *construct_stack()
{

    struct nw_layer *tap = malloc(sizeof(struct nw_layer));
    struct nw_layer *eth = malloc(sizeof(struct nw_layer));
    struct nw_layer *arp = malloc(sizeof(struct nw_layer));
    struct nw_layer *ip = malloc(sizeof(struct nw_layer));
    struct nw_layer *icmp = malloc(sizeof(struct nw_layer));
    struct nw_layer *udp = malloc(sizeof(struct nw_layer));
    struct nw_layer *tcp = malloc(sizeof(struct nw_layer));

    char *ipv4_addr = DUMMY_IPV4;

    tap->name = "tap";
    tap->send_down = &write_to_tap;
    tap->rcv_up = &send_up_to_ethernet;
    tap->ups_count = 1;
    tap->ups = malloc(tap->ups_count * sizeof(struct nw_layer *));
    tap->ups[0] = eth;
    tap->downs = NULL;
    tap->downs_count = 0;
    tap->context = NULL;

    eth->name = "ethernet";
    eth->send_down = &send_frame_down;
    eth->rcv_up = &receive_frame_up;
    eth->ups_count = 2;
    eth->downs_count = 1;
    eth->ups = malloc(eth->ups_count * sizeof(struct nw_layer *));
    eth->ups[0] = arp;
    eth->ups[1] = ip;
    eth->downs = malloc(eth->downs_count * sizeof(struct nw_layer *));
    eth->downs[0] = tap;
    struct ethernet_context *eth_context = malloc(sizeof(struct ethernet_context));
    memcpy(eth_context->mac, DUMMY_MAC_ADDR, 6);
    eth->context = eth_context;

    arp->name = "arp";
    arp->send_down = &send_arp_down;
    arp->rcv_up = &receive_arp_up;
    arp->ups = NULL;
    arp->ups_count = 0;
    arp->downs_count = 1;
    arp->downs = malloc(arp->downs_count * sizeof(struct nw_layer *));
    arp->downs[0] = eth;
    arp->context = ipv4_addr;
    struct arp_context *arp_ctx = malloc(sizeof(struct arp_context));
    struct arp_table *arp_table_head = NULL;
    arp_ctx->arp_table_head = arp_table_head;
    memcpy(arp_ctx->ipv4_address, DUMMY_IPV4, 4);
    memcpy(arp_ctx->mac_address, DUMMY_MAC_ADDR, 6);
    arp->context = arp_ctx;

    ip->name = "ipv4";
    ip->send_down = &send_ipv4_down;
    ip->rcv_up = &receive_ipv4_up;
    ip->ups_count = 3;
    ip->downs_count = 1;
    ip->ups = malloc(ip->ups_count * sizeof(struct nw_layer *));
    ip->ups[0] = icmp;
    ip->ups[1] = udp;
    ip->ups[2] = tcp;
    ip->downs = malloc(ip->downs_count * sizeof(struct nw_layer *));
    ip->downs[0] = eth;
    ip->context = ipv4_addr;

    icmp->name = "icmp";
    icmp->send_down = &send_icmp_down;
    icmp->rcv_up = &receive_icmp_up;
    icmp->ups = NULL;
    icmp->ups_count = 0;
    icmp->downs_count = 1;
    icmp->downs = malloc(icmp->downs_count * sizeof(struct nw_layer *));
    icmp->downs[0] = ip;

    udp->name = "udp";
    udp->send_down = &send_udp_down;
    udp->rcv_up = &receive_udp_up;
    udp->ups = NULL;
    udp->ups_count = 0;
    udp->downs = (struct nw_layer *[]){ip};
    udp->downs_count = 1;

    tcp->name = "tcp";
    tcp->send_down = &send_tcp_down;
    tcp->rcv_up = &receive_tcp_up;
    tcp->ups = NULL;
    tcp->ups_count = 0;
    tcp->downs = (struct nw_layer *[]){ip};
    tcp->downs_count = 1;

    return tap;
}