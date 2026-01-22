#include "stack_constructor.h"

struct nw_layer *construct_stack(int fd)
{
    struct nw_layer *tap = malloc(sizeof(struct nw_layer));
    struct nw_layer *eth = malloc(sizeof(struct nw_layer));
    struct nw_layer *arp = malloc(sizeof(struct nw_layer));
    struct nw_layer *ip = malloc(sizeof(struct nw_layer));
    struct nw_layer *icmp = malloc(sizeof(struct nw_layer));
    struct nw_layer *udp = malloc(sizeof(struct nw_layer));
    struct nw_layer *tcp = malloc(sizeof(struct nw_layer));

    tap->name = "tap";
    tap->send_down = &write_to_tap;
    tap->rcv_up = &send_up_to_ethernet;
    tap->ups_count = 1;
    tap->ups = malloc(tap->ups_count * sizeof(struct nw_layer *));
    tap->ups[0] = eth;
    tap->downs = NULL;
    tap->downs_count = 0;
    struct tap_context *tap_ctx = malloc(sizeof(struct tap_context));
    tap_ctx->fd = fd;
    tap->context = tap_ctx;

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
    struct ethernet_context *eth_context =
        malloc(sizeof(struct ethernet_context));
    memcpy(eth_context->mac_address, DUMMY_MAC_ADDR, MAC_ADDR_LEN);
    eth->context = eth_context;

    arp->name = "arp";
    arp->send_down = &send_arp_down;
    arp->rcv_up = &receive_arp_up;
    arp->ups = NULL;
    arp->ups_count = 0;
    arp->downs_count = 1;
    arp->downs = malloc(arp->downs_count * sizeof(struct nw_layer *));
    arp->downs[0] = eth;
    struct arp_context *arp_ctx = malloc(sizeof(struct arp_context));
    struct arp_table *arp_table_head = malloc(sizeof(struct arp_table));
    arp_ctx->arp_table = arp_table_head;
    memcpy(arp_ctx->ipv4_address, DUMMY_IPV4, IPV4_ADDR_LEN);
    memcpy(arp_ctx->mac_address, DUMMY_MAC_ADDR, MAC_ADDR_LEN);
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
    struct ipv4_context *ipv4_context = malloc(sizeof(struct ipv4_context));
    memcpy(ipv4_context->ipv4_address, DUMMY_IPV4, IPV4_ADDR_LEN);
    ipv4_context->arp_layer = arp;
    ipv4_context->routing_table = create_routing_table();
    ip->context = ipv4_context;

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
    udp->downs_count = 1;
    udp->downs = malloc(udp->downs_count * sizeof(struct nw_layer *));
    udp->downs[0] = ip;

    tcp->name = "tcp";
    tcp->send_down = &send_tcp_down;
    tcp->rcv_up = &receive_tcp_up;
    tcp->ups = NULL;
    tcp->ups_count = 0;
    tcp->downs_count = 1;
    tcp->downs = malloc(tcp->downs_count * sizeof(struct nw_layer *));
    tcp->downs[0] = ip;

    return tap;
}