#include "ethernet.h"

pkt_result receive_frame_up(struct nw_layer *self, struct pkt *packet)
{
    struct ethernet_header *header = (struct ethernet_header *)packet->data;
    print_incoming(header);

    if (relevant_destination_mac(header->dest_mac, self) == false)
    {
        printf("Frame not relevant for us. Ignoring.\n");
        return FRAME_TARGET_NOT_RELEVANT;
    }

    packet->offset += sizeof(struct ethernet_header);

    unsigned short ethertype = ntohs(header->ethertype);
    switch (ethertype)
    {
        case IPV4:
            printf("This is an IPv4 packet.\n");
            return send_to_ipv4(self, packet);
            break;
        case ARP:
            printf("This is an ARP packet.\n");
            return send_to_arp(self, packet);
            break;
        case IPV6:
            return ETHERTYPE_NOT_SUPPORTED;
            printf("This is an IPv6 packet. Not supported yet\n");
            break;
        case VLAN:
            return ETHERTYPE_NOT_SUPPORTED;
            printf("This is a VLAN tagged packet. Not supported yet\n");
            break;
        default:
            printf("Unknown Ethertype: 0x%04x\n", ethertype);
            return ETHERTYPE_NOT_SUPPORTED;
            break;
    }
}

pkt_result send_frame_down(struct nw_layer *self, struct pkt *packet)
{
    struct ethernet_header *header =
        (struct ethernet_header *)(packet->data + packet->offset);
    struct ethernet_context *context = (struct ethernet_context *)self->context;

    header->ethertype = packet->metadata.ethertype;
    memcpy(header->dest_mac, packet->metadata.dest_mac, MAC_ADDR_LEN);
    memcpy(header->src_mac, context->mac_address, MAC_ADDR_LEN);
    return self->downs[0]->send_down(self->downs[0], packet);
}

pkt_result send_to_ipv4(struct nw_layer *self, struct pkt *packet)
{
    for (size_t i = 0; i < self->ups_count; i++)
        if (strcmp(self->ups[i]->name, "ipv4") == 0)
            return self->ups[i]->rcv_up(self->ups[i], packet);

    return LAYER_NAME_NOT_FOUND;
}

pkt_result send_to_arp(struct nw_layer *self, struct pkt *packet)
{
    for (size_t i = 0; i < self->ups_count; i++)
        if (strcmp(self->ups[i]->name, "arp") == 0)
            return self->ups[i]->rcv_up(self->ups[i], packet);

    return LAYER_NAME_NOT_FOUND;
}

// Only procees frames sent to stack's MAC or ipv4 broadcast
// No ipv6 mulicast support yet
bool relevant_destination_mac(mac_address dest_mac, struct nw_layer *self)
{
    struct ethernet_context *context = (struct ethernet_context *)self->context;

    if (memcmp(dest_mac, IPV4_BROADCAST_MAC, MAC_ADDR_LEN) == 0 ||
        memcmp(dest_mac, context->mac_address, MAC_ADDR_LEN) == 0)
        return true;
    return false;
}

void print_incoming(struct ethernet_header *header)
{
    printf("Incoming Ethernet Frame:\n");
    printf("Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", header->src_mac[0],
           header->src_mac[1], header->src_mac[2], header->src_mac[3],
           header->src_mac[4], header->src_mac[5]);
    printf("Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           header->dest_mac[0], header->dest_mac[1], header->dest_mac[2],
           header->dest_mac[3], header->dest_mac[4], header->dest_mac[5]);
    printf("Ethertype: 0x%04x\n", ntohs(header->ethertype));
}