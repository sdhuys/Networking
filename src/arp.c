#include "arp.h"

int receive_arp_up(struct nw_layer *self, struct pkt *packet)
{
    struct arp_header *arp_header = (struct arp_header *)&packet->data[packet->offset];

    uint16_t hw_type = ntohs(arp_header->hw_type);

    // ONLY SUPPORTING ETHERNET
    if (hw_type != 1)
    {
        printf("Unsupported hardware type: %u\n", hw_type);
        return -1;
    }

    uint16_t op = ntohs(arp_header->operation);
    uint16_t proto_type = ntohs(arp_header->proto_type);
    
    unsigned char proto_addr_len = arp_header->proto_addr_len;

    if (op == ARP_REQUEST)
    {
        unsigned char proto_my_address[proto_addr_len];

        switch (proto_type)
        {
            case IPV4:
                memcpy(proto_my_address, ((struct arp_context *)self->context)->ipv4_address, proto_addr_len);
                break;
            default:
                printf("Unsupported protocol type in ARP request: 0x%04x\n", proto_type);
                return -1;
        }

        if (memcmp(arp_header->dest_ip, proto_my_address, proto_addr_len) != 0)
        {
            printf("ARP request not for us. Ignoring.\n\n");
            return -1;
        }

        printf("Received ARP REQUEST\n");
        struct pkt *arp_response = create_arp_response(packet, arp_header, ((struct arp_context *)self->context)->mac_address);
        send_arp_down(self, arp_response);
    }

    else if (op == ARP_REPLY)
    {
        printf("Received ARP REPLY\n");
        return 0;
    }

    else
    {
        printf("Unknown ARP operation: %u\n", op);
        return -1;
    }
}

struct pkt *create_arp_response(struct pkt *packet, struct arp_header *header, unsigned char *requested_address)
{
    header->operation = htons(ARP_REPLY);
    memcpy(header->dest_mac, header->src_mac, header->hw_addr_len);
    memcpy(header->src_mac, requested_address, header->hw_addr_len);
    ipv4_address temp_ip;
    memcpy(temp_ip, header->dest_ip, header->proto_addr_len);
    memcpy(header->dest_ip, header->src_ip, header->proto_addr_len);
    memcpy(header->src_ip, temp_ip, header->proto_addr_len);
    
    return packet;
}

void print_arp_header(struct arp_header *arp_header)
{
    printf("ARP Header:\n");
    printf("  Hardware Type: %u\n", ntohs(arp_header->hw_type));
    printf("  Protocol Type: 0x%04x\n", ntohs(arp_header->proto_type));
    printf("  Hardware Address Length: %u\n", arp_header->hw_addr_len);
    printf("  Protocol Address Length: %u\n", arp_header->proto_addr_len);
    printf("  Operation: %u\n", ntohs(arp_header->operation));

    printf("  Sender MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           arp_header->src_mac[0], arp_header->src_mac[1],
           arp_header->src_mac[2], arp_header->src_mac[3],
           arp_header->src_mac[4], arp_header->src_mac[5]);

    printf("  Sender IP: %u.%u.%u.%u\n",
           arp_header->src_ip[0], arp_header->src_ip[1],
           arp_header->src_ip[2], arp_header->src_ip[3]);

    printf("  Target MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           arp_header->dest_mac[0], arp_header->dest_mac[1],
           arp_header->dest_mac[2], arp_header->dest_mac[3],
           arp_header->dest_mac[4], arp_header->dest_mac[5]);

    printf("  Target IP: %u.%u.%u.%u\n\n",
           arp_header->dest_ip[0], arp_header->dest_ip[1],
           arp_header->dest_ip[2], arp_header->dest_ip[3]);
}

int send_arp_down(struct nw_layer *self, struct pkt *packet)
{
    printf("SENDING RESPONSE DOWN \n");
    print_arp_header((struct arp_header *)&packet->data[packet->offset]);

    packet->offset -= sizeof(struct ethernet_header);
    self->downs[0]->send_down(self->downs[0], packet);

    return 0;
}