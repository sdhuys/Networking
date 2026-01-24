#include "ipv4.h"

pkt_result receive_ipv4_up(struct nw_layer *self, struct pkt *packet)
{
    struct ipv4_header *header =
        (struct ipv4_header *)(packet->data + packet->offset);

    memcpy(packet->metadata.src_ip, header->src_ip, IPV4_ADDR_LEN);

    if (header->version_ihl >> 4 != IPV4_V)
        return IP_VERSION_MISMATCH;

    size_t header_len = (header->version_ihl & 0x0F);
    if (header_len != IPV4_HEADER_NO_OPTIONS_LEN)
        return IP_OPTIONS_NOT_SUPPORTED;

    // dscp_ecn ignored

    uint16_t flags_fragment_offset = ntohs(header->flags_fragment_offset);
    bool more_fragments = (flags_fragment_offset >> 13) & 0x1;
    uint16_t offset = flags_fragment_offset & 0x1FFF;
    if (more_fragments || (offset != 0))
        return IP_FRAGMENTATION_NOT_SUPPORTED;

    if (calc_header_checksum(header, header_len) != 0)
        return IP_CHECKSUM_ERROR;

    if (!relevant_destination_ip(header->dest_ip, self))
        return IP_DEST_NOT_RELEVANT;

    packet->offset += header_len * 4; // == sizeof(struct ipv4_header) since we
                                      // enforece NO OPTIONS in header
    packet->len -= header_len * 4;
    switch (header->protocol)
    {
        case ICMP:
            return send_to_icmp(self, packet);
        case TCP:
            return NOT_IMPLEMENTED_YET;
        case UDP:
            return NOT_IMPLEMENTED_YET;
        case IGMP:
        case ENCAP:
        case OSPF:
        case SCTP:
            return IP_HDR_TRANSPORT_PROT_NOT_SUPPORTED;
        default:
            return IP_HDR_UNKNOWN_TRANSPORT_PROT;
    };
}

pkt_result send_to_icmp(struct nw_layer *self, struct pkt *packet)
{
    for (size_t i = 0; i < self->ups_count; i++)
        if (strcmp(self->ups[i]->name, "icmp") == 0)
            return self->ups[i]->rcv_up(self->ups[i], packet);

    return LAYER_NAME_NOT_FOUND;
}

pkt_result send_ipv4_down(struct nw_layer *self, struct pkt *packet)
{
    packet->metadata.ethertype = htons(IPV4);

    struct ipv4_context *ipv4_context = (struct ipv4_context *)self->context;
    struct nw_layer *arp_layer = ipv4_context->arp_layer;
    struct arp_context *arp_context = arp_layer->context;

    struct arp_table *arp_table = arp_context->arp_table;

    // CREATE IP HEADER, CURRENTLY ONLY WORKS FOR REPLIES
    // reusing incoming header
    struct ipv4_header *header =
        (struct ipv4_header *)(packet->data + packet->offset);
    memcpy(header->dest_ip, packet->metadata.src_ip, IPV4_ADDR_LEN);
    memcpy(header->src_ip, ipv4_context->ipv4_addr, IPV4_ADDR_LEN);
    packet->offset -= sizeof(struct ethernet_header);
    packet->len += sizeof(struct ethernet_header);

    ipv4_address next_hop;
    get_next_hop(self, header, &next_hop);

    struct arp_table_node *dest_ip_node = query_arp_table(arp_table, next_hop);
    if (dest_ip_node == NULL)
    {
        dest_ip_node = insert_incomplete_for_ip(arp_table, next_hop);
        struct pkt *arp_request = create_arp_request_for(arp_layer, next_hop);
        send_arp_down(arp_layer, arp_request);
    }
    if (dest_ip_node->status == ARP_INCOMPLETE)
        return add_pkt_to_q(dest_ip_node, packet);

    memcpy(packet->metadata.dest_mac, dest_ip_node->mac_address, MAC_ADDR_LEN);

    return self->downs[0]->send_down(self->downs[0], packet);
}

bool relevant_destination_ip(ipv4_address dest_ip, struct nw_layer *self)
{
    struct ipv4_context *context = (struct ipv4_context *)self->context;

    if (memcmp(dest_ip, IPV4_BROADCAST_MAC, IPV4_ADDR_LEN) == 0 ||
        memcmp(dest_ip, context->ipv4_addr, IPV4_ADDR_LEN) == 0)
        return true;
    return false;
}

void get_next_hop(struct nw_layer *self, struct ipv4_header *header,
                  ipv4_address *out_next_hop)
{
    struct ipv4_context *context = (struct ipv4_context *)self->context;
    struct route *routes = context->routing_table;
    ipv4_address *best_route_ip_ptr = NULL;

    int longest_prefix = -1;

    uint32_t int_ip;
    memcpy(&int_ip, header->dest_ip, IPV4_ADDR_LEN);

    for (size_t i = 0; i < context->routes_amount; i++)
    {
        struct route *route = &routes[i];
        uint32_t mask = route->prefix_len != 0
                            ? (0xFFFFFFFF << (32 - route->prefix_len))
                            : 0;

        if (route->prefix_len > longest_prefix &&
            ((int_ip & htonl(mask))) == route->prefix)
        {
            longest_prefix = route->prefix_len;
            if (route->type == ROUTE_VIA)
                best_route_ip_ptr = (ipv4_address *)(&(route->gateway));
            else
                best_route_ip_ptr = &header->dest_ip;
        }
    }
    memcpy(out_next_hop, best_route_ip_ptr, IPV4_ADDR_LEN);
}

// calculate one's complement of 16bit one's complement sum of all 16bit units
// in header header
// length in 32bit units => no odd trailing byte possible
uint16_t calc_header_checksum(struct ipv4_header *header, size_t header_len)
{
    // calc sum of all 16 bit units in header
    uint32_t sum = 0;
    uint16_t *ptr = (uint16_t *)header;

    for (uint i = 0; i < header_len * 2; i++)
        sum += ptr[i];

    // calc 16bit one's complement of sum (adding carries beyond 16 bits back)
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    // one's complement
    return (uint16_t)~sum;
}