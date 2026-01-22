#include "icmp.h"

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
    header->checksum = calc_packet_checksum(header, len);
}

uint16_t calc_packet_checksum(void *data, size_t len)
{
    // calc sum of all 16 bit units in header
    uint32_t sum = 0;
    uint16_t *ptr = (uint16_t *)data;
    for (uint i = 0; i < len; i++)
        sum += ptr[i];

    // calc 16bit one's complement of sum (adding carries beyond 16 bits back)
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    // one's complement
    return (uint16_t)~sum;
}