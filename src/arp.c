#include "arp.h"

pkt_result receive_arp_up(struct nw_layer *self, struct pkt *packet)
{
    struct arp_data *arp_data =
        (struct arp_data *)(packet->data + packet->offset);
    uint16_t hw_type = ntohs(arp_data->hw_type);

    // ONLY SUPPORTING ETHERNET
    if (hw_type != ETHERNET)
        return ARP_HW_TYPE_NOT_SUPPORTED;

    uint16_t proto_type = ntohs(arp_data->proto_type);
    // ONLY SUPPORTING IVP4
    if (proto_type != IPV4)
        return ARP_PRTCL_TYPE_NOT_SUPPORTED;

    uint16_t op = ntohs(arp_data->operation);
    unsigned char proto_addr_len = arp_data->proto_addr_len;
    unsigned char hw_addr_len = arp_data->hw_addr_len;
    if (proto_addr_len != IPV4_ADDR_LEN || hw_addr_len != MAC_ADDR_LEN)
        return ARP_MALFORMED;

    struct arp_context *cntx = (struct arp_context *)self->context;

    if (op == ARP_REQUEST)
    {
        if (memcmp(arp_data->target_ip, cntx->ipv4_address, proto_addr_len) !=
            0)
            return ARP_RQST_TARGET_NOT_RELEVANT;

        inc_arp_request_to_reply(packet, arp_data, cntx->mac_address);
        return send_arp_down(self, packet);
    }

    else if (op == ARP_REPLY)
    {
        struct arp_table_node *arp_entry =
            query_arp_table(cntx->arp_table, arp_data->src_ip);

        // Unsolicited ARP responses dropped
        if (arp_entry == NULL || arp_entry->status == ARP_REACHABLE)
            return ARP_REPLY_NOT_RQSTD;

        complete_arp_table_node(arp_entry, arp_data->src_mac);
        flush_q(self, arp_entry);
        return ARP_TABLE_UPDATED_Q_FLUSHED;
    }

    else
        return ARP_UNKNOWN_OPERATION;
}

void flush_q(struct nw_layer *self, struct arp_table_node *arp_entry)
{
    struct queue_entry *current = arp_entry->pending_packets;
    struct queue_entry *next;
    while (current != NULL)
    {
        next = current->next;
        memcpy(current->packet->metadata.dest_mac, arp_entry->mac_address,
               MAC_ADDR_LEN);
        current->packet->metadata.ethertype = htons(IPV4);

        self->downs[0]->send_down(self->downs[0], current->packet);
        free(current);
        current = next;
    }
    arp_entry->pending_packets = NULL;
    arp_entry->pending_tail = NULL;
}

struct arp_table_node *insert_incomplete_for_ip(struct arp_table *table,
                                                ipv4_address dest_ip)
{
    struct arp_table_node *new = malloc(sizeof(struct arp_table_node));
    if (new == NULL)
        return NULL;

    memcpy(new->ipv4_address, dest_ip, IPV4_ADDR_LEN);
    new->status = ARP_INCOMPLETE;
    new->pending_packets = NULL;
    new->pending_tail = NULL;
    new->last_updated = time(NULL);
    new->next = table->head;
    table->head = new;
    return new;
}

pkt_result add_pkt_to_q(struct arp_table_node *node, struct pkt *packet)
{
    // freed after flushing
    struct queue_entry *new = malloc(sizeof(struct queue_entry));
    new->next = NULL;
    new->packet = packet;

    struct queue_entry *curr = node->pending_packets;
    if (curr == NULL)
        node->pending_packets = new;
    else
        node->pending_tail->next = new;
    node->pending_tail = new;

    return PACKET_QUEUED;
}

struct arp_table_node *query_arp_table(struct arp_table *table, ipv4_address ip)
{
    struct arp_table_node *node = table->head;
    for (; node != NULL; node = node->next)
        if (memcmp(ip, node->ipv4_address, IPV4_ADDR_LEN) == 0)
            return node;

    return NULL;
}

void complete_arp_table_node(struct arp_table_node *entry, mac_address src_mac)
{
    memcpy(entry->mac_address, src_mac, MAC_ADDR_LEN);
    entry->last_updated = time(NULL);
    entry->status = ARP_REACHABLE;
}

void inc_arp_request_to_reply(struct pkt *packet, struct arp_data *header,
                              mac_address requested_address)
{
    memcpy(packet->metadata.dest_mac, header->src_mac, header->hw_addr_len);

    header->operation = htons(ARP_REPLY);
    memcpy(header->target_mac, header->src_mac, header->hw_addr_len);
    memcpy(header->src_mac, requested_address, header->hw_addr_len);
    ipv4_address temp_ip;
    memcpy(temp_ip, header->target_ip, header->proto_addr_len);
    memcpy(header->target_ip, header->src_ip, header->proto_addr_len);
    memcpy(header->src_ip, temp_ip, header->proto_addr_len);
}

void print_arp_header(struct arp_data *arp_header)
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

    printf("  Sender IP: %u.%u.%u.%u\n", arp_header->src_ip[0],
           arp_header->src_ip[1], arp_header->src_ip[2], arp_header->src_ip[3]);

    printf("  Target MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           arp_header->target_mac[0], arp_header->target_mac[1],
           arp_header->target_mac[2], arp_header->target_mac[3],
           arp_header->target_mac[4], arp_header->target_mac[5]);

    printf("  Target IP: %u.%u.%u.%u\n\n", arp_header->target_ip[0],
           arp_header->target_ip[1], arp_header->target_ip[2],
           arp_header->target_ip[3]);
}

struct pkt *create_arp_request_for(struct nw_layer *self,
                                   ipv4_address target_ip)
{
    struct pkt *pkt = malloc(sizeof(struct pkt));
    if (pkt == NULL)
        return NULL;

    size_t eth_sz = sizeof(struct ethernet_header);
    size_t arp_sz = sizeof(struct arp_data);

    pkt->data = malloc(eth_sz + arp_sz);
    if (pkt->data == NULL)
    {
        free(pkt);
        return NULL;
    }

    memcpy(pkt->metadata.dest_mac, IPV4_BROADCAST_MAC, MAC_ADDR_LEN);

    pkt->offset = eth_sz;
    pkt->len = eth_sz + arp_sz;

    struct arp_context *arp_context = (struct arp_context *)self->context;
    struct arp_data *arp = (struct arp_data *)(pkt->data + pkt->offset);

    arp->hw_type = htons(ETHERNET);
    arp->proto_type = htons(IPV4);
    arp->hw_addr_len = MAC_ADDR_LEN;
    arp->proto_addr_len = IPV4_ADDR_LEN;
    arp->operation = htons(ARP_REQUEST);

    memcpy(arp->src_mac, arp_context->mac_address, MAC_ADDR_LEN);
    memcpy(arp->src_ip, arp_context->ipv4_address, IPV4_ADDR_LEN);
    memcpy(arp->target_ip, target_ip, IPV4_ADDR_LEN);
    memset(arp->target_mac, 0x00, MAC_ADDR_LEN);

    return pkt;
}

pkt_result send_arp_down(struct nw_layer *self, struct pkt *packet)
{
    printf("SENDING ARP DOWN \n");
    print_arp_header((struct arp_data *)&packet->data[packet->offset]);
    packet->metadata.ethertype = htons(ARP);
    packet->offset -= sizeof(struct ethernet_header);
    return self->downs[0]->send_down(self->downs[0], packet);
}