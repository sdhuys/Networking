#include "ethernet.h"

int receive_frame_up(struct nw_layer *self, const struct pkt *data)
{
    const struct ethernet_header *header = (const struct ethernet_header *)data->data;

    if (relevant_destination_mac(header->dest_mac, self) == false)
    {
        printf("Frame not relevant for us. Ignoring.\n");
        free(data->data);
        return -1;
    }

    unsigned short ethertype = ntohs(header->ethertype);
    switch (ethertype)
    {
        case IPV4:
            printf("This is an IPv4 packet.\n");
            break;
        case ARP:
            printf("This is an ARP packet.\n");
            break;
        case IPV6:
            printf("This is an IPv6 packet. Not supported yet\n");
            break;
        default:
            printf("Unknown Ethertype: 0x%04x\n", ethertype);
            break;
    }

    print_incoming(header);

    return 0;
}

int send_frame_down(struct nw_layer *self, const struct pkt *data)
{
    return 0;
}

// Only procees frames sent to stack's MAC or ipv4 broadcast
// No ipv6 mulicast support yet
bool relevant_destination_mac(const mac_address dest_mac, struct nw_layer *self)
{
    struct ethernet_context *context = (struct ethernet_context *)self->context;

    if (memcmp(dest_mac, IPV4_BROADCAST_MAC, 6) == 0 || memcmp(dest_mac, context->mac, 6) == 0)
        return true;
    return false;
}

void print_incoming(const struct ethernet_header *header)
{
    printf("Incoming Ethernet Frame:\n");
    printf("Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           header->src_mac[0], header->src_mac[1],
           header->src_mac[2], header->src_mac[3],
           header->src_mac[4], header->src_mac[5]);
    printf("Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           header->dest_mac[0], header->dest_mac[1],
           header->dest_mac[2], header->dest_mac[3],
           header->dest_mac[4], header->dest_mac[5]);
    printf("Ethertype: 0x%04x\n\n", ntohs(header->ethertype));
}