#pragma once
#include <stddef.h>

struct stack;
struct nw_interface;

#ifdef __cplusplus
extern "C" {
#endif

struct static_route;

struct stack *construct_stack(struct nw_interface *interfaces,
			      size_t if_count,
			      struct static_route *statics,
			      size_t static_count);
#ifdef __cplusplus
}
#endif
