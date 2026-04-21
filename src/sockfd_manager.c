#include "sockfd_manager.h"
#include <stdlib.h>

int sockfd_manager_init(struct sockfd_manager *fd_mgr)
{
	fd_mgr->fd_sockets = calloc(MAX_SOCKETS, sizeof(struct socket_handle));
	if (!fd_mgr->fd_sockets)
		return -1;

	fd_mgr->free_stack = malloc(sizeof(int) * MAX_SOCKETS);
	if (!fd_mgr->free_stack) {
		free(fd_mgr->fd_sockets);
		return -1;
	}

	for (int i = 0; i < MAX_SOCKETS; i++)
		fd_mgr->free_stack[i] = i;

	fd_mgr->top_free_index = MAX_SOCKETS - 1;
	pthread_mutex_init(&fd_mgr->fds_lock, NULL);

	return 0;
}

int get_sockfd(struct sockfd_manager *fd_mgr)
{
	pthread_mutex_lock(&fd_mgr->fds_lock);

	if (fd_mgr->top_free_index == (size_t)-1) {
		pthread_mutex_unlock(&fd_mgr->fds_lock);
		return -1;
	}

	int fd = fd_mgr->free_stack[fd_mgr->top_free_index--];
	pthread_mutex_unlock(&fd_mgr->fds_lock);
	return fd;
}

void sockfd_free(struct sockfd_manager *fd_mgr, int fd)
{
	pthread_mutex_lock(&fd_mgr->fds_lock);

	fd_mgr->fd_sockets[fd].sock = NULL;
	fd_mgr->fd_sockets[fd].ops = NULL;
	fd_mgr->free_stack[++fd_mgr->top_free_index] = fd;

	pthread_mutex_unlock(&fd_mgr->fds_lock);
}

void assign_sock_h(struct sockfd_manager *fd_mgr, int fd, struct socket_handle h)
{
	pthread_mutex_lock(&fd_mgr->fds_lock);
	fd_mgr->fd_sockets[fd] = h;
	pthread_mutex_unlock(&fd_mgr->fds_lock);
}

int get_socket_handle(struct sockfd_manager *fd_mgr, int fd, struct socket_handle *out)
{
	if (fd < 0 || fd >= MAX_SOCKETS)
		return -1;

	pthread_mutex_lock(&fd_mgr->fds_lock);

	struct socket_handle h = fd_mgr->fd_sockets[fd];
	if (!h.sock || !h.ops) {
		pthread_mutex_unlock(&fd_mgr->fds_lock);
		return -1;
	}

	*out = h;
	pthread_mutex_unlock(&fd_mgr->fds_lock);
	return 0;
}
