#include "buffer_pool.h"
#include "ring_buffer.h"
#include "socket_manager.h"
#include "udp_socket.h"
#include "types.h"

void *stack_transmission_loop(void *arg);