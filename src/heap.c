#include "heap.h"

#define PARENT(i) (((i) - 1) / 2)
#define LEFT(i) (2 * (i) + 1)
#define RIGHT(i) (2 * (i) + 2)

struct min_heap *heap_create(uint16_t capacity)
{
	struct min_heap *h = malloc(sizeof(struct min_heap));
	if (!h)
		return NULL;

	h->nodes = malloc(sizeof(struct heap_node *) * capacity);
	if (!h->nodes) {
		free(h);
		return NULL;
	}

	h->count = 0;
	h->capacity = capacity;
	return h;
}

void heap_destroy(struct min_heap *h)
{
	if (h) {
		free(h->nodes);
		free(h);
	}
}

void heapify_up(struct min_heap *heap, uint32_t i)
{
	struct heap_node *node = heap->nodes[i];

	uint32_t p = PARENT(i);
	while (i > 0 && node->priority < heap->nodes[p]->priority) {
		heap->nodes[i] = heap->nodes[p];
		heap->nodes[i]->index = i;
		i = p;
		p = PARENT(p);
	}
	heap->nodes[i] = node;
	node->index = i;
}

void heapify_down(struct min_heap *heap, uint32_t i)
{
	struct heap_node *n = heap->nodes[i];
	uint32_t l = LEFT(i);

	while (l < heap->count) {
		uint32_t r = RIGHT(i);
		uint32_t smallest = l;

		if (r < heap->count && heap->nodes[r]->priority < heap->nodes[l]->priority)
			smallest = r;

		if (n->priority <= heap->nodes[smallest]->priority)
			break;

		heap->nodes[i] = heap->nodes[smallest];
		heap->nodes[i]->index = i;

		i = smallest;
		l = LEFT(i);
	}
	heap->nodes[i] = n;
	n->index = i;
}

void heap_remove(struct min_heap *h, struct heap_node *node)
{
	uint32_t i = node->index;
	if (i >= h->count)
		return;

	uint32_t last = --h->count;
	node->index = NODE_NOT_IN_HEAP;
	
	if (i == last)
		return; // removed last item, heap still instact

	h->nodes[i] = h->nodes[last];
	h->nodes[i]->index = i;
	if (i > 0 && h->nodes[i]->priority < h->nodes[PARENT(i)]->priority)
		heapify_up(h, i);
	else
		heapify_down(h, i);
}

void heap_update(struct min_heap *h, struct heap_node *node, uint64_t new_priority)
{
	if (node->index == NODE_NOT_IN_HEAP)
		return;

	uint64_t old_priority = node->priority;
	node->priority = new_priority;

	if (new_priority < old_priority)
		heapify_up(h, node->index);
	else if (new_priority > old_priority)
		heapify_down(h, node->index);
}

// append and heapify up
bool heap_push(struct min_heap *h, struct heap_node *node, uint64_t priority)
{
	if (h->count == h->capacity || node->index != NODE_NOT_IN_HEAP)
		return false;
		
	node->priority = priority;
	node->index = h->count;
	h->nodes[h->count++] = node;
	heapify_up(h, node->index);
	return true;
}

// remove min element, move last to root, heapify down
struct heap_node *heap_pop(struct min_heap *h)
{
	if (h->count == 0)
		return NULL;

	struct heap_node *n = h->nodes[0];
	heap_remove(h, n);
	return n;
}

struct heap_node *heap_peek(struct min_heap *h)
{
    if (h->count == 0)
        return NULL;
    
    return h->nodes[0];
}