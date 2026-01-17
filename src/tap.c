#include "tap.h"

int start_listening(int fd, struct nw_layer *tap)
{
    const int MAX_ETH_FRAME_SIZE = 1518;
    tap->context = (void *)(intptr_t)fd;
    for (;;)
    {
        unsigned char *buffer = malloc(MAX_ETH_FRAME_SIZE);
        ssize_t nread = read(fd, buffer, MAX_ETH_FRAME_SIZE);
        if (nread < 0)
        {
            perror("Reading from TAP interface");
            close(fd);
            return -1;
        }
        struct pkt data =
        {
            .data = buffer,
            .offset = 0,
            .len = (size_t)nread
        };

        tap->rcv_up(tap, &data);
    }
}

int send_up_to_ethernet(struct nw_layer *tap, const struct pkt *data)
{
    tap->ups[0]->rcv_up(tap->ups[0], data);
    return 0;
}

int write_to_tap(struct nw_layer *tap, const struct pkt *data)
{
    int fd = (int)(intptr_t)tap->context;
    ssize_t nwrite = write(fd, data->data, data->len);
    if (nwrite < 0)
    {
        perror("Writing to TAP interface");
        close(fd);
        return -1;
    }
    return 0;
}