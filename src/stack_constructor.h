#pragma once
#include <stddef.h>

struct stack;
struct nw_interface;

#ifdef __cplusplus
extern "C" {
#endif

struct stack *construct_stack(struct nw_interface *interface_array, size_t if_count);

#ifdef __cplusplus
}
#endif
