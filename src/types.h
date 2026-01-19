#pragma once
#include <stddef.h>
#include <stdint.h>

// ===== Definitions & Constants =====
#define MAC_ADDR_LEN 6
#define IPV4_ADDR_LEN 4

#define ARP_REQUEST 1
#define ARP_REPLY 2

#define MAX_ETH_FRAME_SIZE 1518

#define IPV4 0x0800
#define ARP 0x0806
#define IPV6 0x86DD
#define VLAN 0x8100

extern const unsigned char IPV4_BROADCAST_MAC[MAC_ADDR_LEN];
extern const unsigned char DUMMY_IPV4[4];
extern const unsigned char DUMMY_MAC_ADDR[6];

// ===== Common Types =====
typedef unsigned char mac_address[MAC_ADDR_LEN];
typedef unsigned char ipv4_address[IPV4_ADDR_LEN];
typedef uint16_t protocol_type;

// ===== Packet Structures =====
struct pkt_metadata
{
    mac_address src_mac;
    mac_address dest_mac;

    ipv4_address src_ip;
    ipv4_address dest_ip;
};

struct pkt
{
    unsigned char *data;    //Should only be modified once we go back down the stack
    size_t len; 
    size_t offset;          //Offset to the start of the current layer's header within data, no need to strip headers and copy
    struct pkt_metadata *metadata;
};

// ===== General Network Layer Structure =====
struct nw_layer
{
    char *name;
    int (*send_down)(struct nw_layer *self, struct pkt *packet);
    int (*rcv_up)(struct nw_layer *self, struct pkt *packet);
    struct nw_layer **ups;
    struct nw_layer **downs;
    size_t ups_count;
    size_t downs_count;
    void *context;
};

// ===== TAP Interface =====
struct tap_context
{
    int fd;
};

// ===== Ethernet Layer =====
struct ethernet_context
{
    mac_address mac;
};


struct ethernet_header
{
    mac_address dest_mac;
    mac_address src_mac;
    protocol_type ethertype;
} __attribute__((packed));


// ===== ARP Layer =====
struct arp_table
{
    unsigned char ipv4_address[4];
    unsigned char mac_address[6];
    struct arp_table *next;
};

struct arp_context
{
    unsigned char ipv4_address[4];
    unsigned char mac_address[6];
    struct arp_table *arp_table_head;
};

struct arp_header
{
    uint16_t hw_type;
    uint16_t proto_type;
    unsigned char hw_addr_len;
    unsigned char proto_addr_len;
    uint16_t operation;
    mac_address src_mac;
    ipv4_address src_ip;
    mac_address dest_mac;
    ipv4_address dest_ip;
} __attribute__((packed));

// ===== IPv4 Layer =====
struct ipv4_context
{
    ipv4_address ipv4_address;
};
struct ipv4_header
{
    unsigned char version_ihl;
    unsigned char tos;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_fragment_offset;
    unsigned char ttl;
    unsigned char protocol;
    uint16_t header_checksum;
    ipv4_address src_ip;
    ipv4_address dest_ip;
} __attribute__((packed));