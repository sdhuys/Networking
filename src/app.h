#pragma once
#include "types.h"

void start_app(struct socket_manager_t *socket_manager);
// ===== Protocol-agnostic socket API =====

// Open a socket of the given type (SOCK_UDP or SOCK_TCP).
// Returns a socket handle that must be retained/released correctly.
struct socket_handle_t app_socket_open(struct socket_manager_t *socket_manager, socket_type_t type, uint16_t local_port);

// Close a socket handle, releasing its resources.
// After this, the handle is invalid.
void app_socket_close(struct socket_manager_t *socket_manager, struct socket_handle_t socket_h);

// Send data through a socket
pkt_result app_socket_send(struct socket_handle_t sock, unsigned char *data, size_t len);

// Receive next packet from a socket's receive buffer.
// Returns a pointer to a packet; ownership remains with the API until released.
struct pkt_t *app_socket_receive(struct socket_handle_t sock);

// Release a packet previously returned by app_socket_receive.
void app_socket_release_packet(struct pkt_t *pkt);
