#include "icmp.h"
#include <stdio.h>

pkt_result send_icmp_down(struct nw_layer *self, struct pkt *packet)
{
    packet->offset -= sizeof(struct ipv4_header);
    return self->downs[0]->send_down(self->downs[0], packet);
}

pkt_result receive_icmp_up(struct nw_layer *self, struct pkt *packet)
{
    struct icmp_header *header =
        (struct icmp_header *)(packet->data + packet->offset);
    size_t icmp_len = packet->len - packet->offset;

    if (calc_packet_checksum(header, icmp_len) != 0)
        return ICMP_CHECKSUM_ERROR;
        
    switch (header->type)
    {
        case ECHO_REPLY:
            return ICMP_ECHO_REPLY_RCVD;
        case ECHO_REQUEST:
            memcpy(packet->metadata.dest_ip, packet->metadata.src_ip,
                   IPV4_ADDR_LEN);

            echo_request_to_reply(packet, header, icmp_len);
            return send_icmp_down(self, packet);
        default:
            return ICMP_TYPE_NOT_SUPPORTED;
    }
}

void echo_request_to_reply(struct pkt *packet, struct icmp_header *header,
                           size_t len)
{
    memcpy(packet->metadata.dest_ip, packet->metadata.src_ip, IPV4_ADDR_LEN);
    header->type = 0;
    header->code = 0;
    header->checksum = 0;
    header->checksum = htons(calc_packet_checksum(header, len));
}

uint16_t calc_packet_checksum(void *data, size_t len)
{
    const uint8_t *bytes = data;
    uint32_t sum = 0;

    // Sum 16-bit words
    while (len >= 2)
    {
        sum += (bytes[0] << 8) | bytes[1];
        bytes += 2;
        len -= 2;
    }

    // Handle odd trailing byte
    if (len == 1)
        sum += bytes[0] << 8;

    // Fold carries
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return (uint16_t)~sum;
}
