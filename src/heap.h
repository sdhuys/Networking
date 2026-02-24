#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define NODE_NOT_IN_HEAP 0xFFFFFFFF
#define HEAP_SIZE_DEFAULT 0xFFFF

struct heap_node {
	uint64_t priority;
	uint32_t index; // 0xFFFFFFFF = not in heap
};

struct min_heap {
    struct heap_node **nodes; // array of pointers to nodes
    size_t count;
    size_t capacity;
};

struct min_heap *heap_create(uint16_t capacity);
void heap_destroy(struct min_heap *heap);
bool heap_push(struct min_heap *h, struct heap_node *node, uint64_t priority);
struct heap_node *heap_pop(struct min_heap *heap);
void heap_remove(struct min_heap *heap, struct heap_node *node);
void heap_update(struct min_heap *h, struct heap_node *node, uint64_t new_priority);
struct heap_node *heap_peek(struct min_heap *h);