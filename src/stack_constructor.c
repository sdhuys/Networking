#include "stack_constructor.h"

struct nw_layer *construct_stack()
{
    struct nw_layer tap = 
    {
        .name = "tap",
        .process_for_up = &send_to_ethernet,
        .process_for_down = NULL,
        .ups = NULL,
        .down = NULL
    };

    struct nw_layer ethernet =
    {
        .name = "ethernet",
        .process_for_up = &read_frame,
        .process_for_down = &create_frame,
        .ups = NULL,
        .down = NULL
    };

    struct nw_layer arp = 
    {
        .name = "arp",
        .process_for_up = &read_arp,
        .process_for_down = &create_arp,
        .ups = NULL,
        .down = NULL
    };
}