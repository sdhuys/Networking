#pragma once
#include "socket_manager.h"
#include <pthread.h>
#include <stddef.h>

#define MAX_SOCKETS 65536

struct sockfd_manager {
	struct socket_handle *fd_sockets; // array of sockets to be indexed into by FD by app side
	pthread_mutex_t fds_lock;
	int *free_stack;
	size_t top_free_index;
};

#ifdef __cplusplus
extern "C" {
#endif

int sockfd_manager_init(struct sockfd_manager *mgr);
int get_sockfd(struct sockfd_manager *mgr);
void sockfd_free(struct sockfd_manager *fd_mgr, int fd);
void assign_sock_h(struct sockfd_manager *fd_mgr, int fd, struct socket_handle h);
int get_socket_handle(struct sockfd_manager *fd_mgr, int fd, struct socket_handle *out);

#ifdef __cplusplus
}
#endif
