#pragma once
#include <stdio.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include "types.h"

int receive_arp_up(struct nw_layer *self, struct pkt *packet);
int send_arp_down(struct nw_layer *self, struct pkt *packet);
void print_arp_header(struct arp_header *arp_header);
struct pkt *create_arp_response(struct pkt *packet, struct arp_header *header, unsigned char *requested_address);