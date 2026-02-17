#pragma once
#include "socket_manager.h"
#include <pthread.h>
#include <stdlib.h>

#define MAX_SOCKETS 65536

struct sockfd_manager_t {
	struct socket_handle_t *fd_sockets; // array of sockets to be indexed into by FD by app side
	pthread_mutex_t fds_lock;
	int *free_stack;
	size_t top_free_index;
};

int sockfd_manager_init(struct sockfd_manager_t *mgr);
int get_sockfd(struct sockfd_manager_t *mgr);
void sockfd_free(struct sockfd_manager_t *fd_mgr, int fd);
void assign_sock_h(struct sockfd_manager_t *fd_mgr, int fd, struct socket_handle_t h);
int get_socket_handle(struct sockfd_manager_t *fd_mgr, int fd, struct socket_handle_t *out);
