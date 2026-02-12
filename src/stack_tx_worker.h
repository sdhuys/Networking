#include "buffer_pool.h"
#include "ring_buffer.h"
#include "socket_manager.h"
#include "types.h"
#include "udp_socket.h"

void *stack_transmission_loop(void *arg);