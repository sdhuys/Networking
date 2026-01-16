#include "ethernet.h"

int read_frame(struct nw_layer *self, struct nw_layer_data *data)
{
    const struct ethernet_frame *frame = (const struct ethernet_frame *)data->data;

    if (relevant_destination_mac(frame->header.dest_mac) == false)
    {
        printf("Frame not relevant for us. Ignoring.\n");
        return -1;
    }

    unsigned short ethertype = ntohs(frame->header.ethertype);

    if (ntohs(frame->header.ethertype) == IPV4)
    {
        printf("This is an IPv4 packet.\n");
    }
    else if (ntohs(frame->header.ethertype) == ARP)
    {
        printf("This is an ARP packet.\n");
    }
    else if (ntohs(frame->header.ethertype) == IPV6)
    {
        printf("This is an IPv6 packet.\n");
    }
    else
    {
        printf("Unknown Ethertype: 0x%04x\n", ntohs(frame->header.ethertype));
    }
    print_incoming(&frame->header);

    return 0;
}

int create_frame(struct nw_layer *self, struct nw_layer_data *data)
{
    return 0;
}

// Only procees frames sent to stack's MAC or ipv4 broadcast
// No ipv6 mulicast support yet
bool relevant_destination_mac(const mac_address dest_mac)
{
    if (memcmp(dest_mac, IPV4_BROADCAST_MAC, 6) == 0 || memcmp(dest_mac, DUMMY_MAC, 6) == 0)
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