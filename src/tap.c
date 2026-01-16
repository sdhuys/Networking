#include "tap.h"

int start_listening(int fd, struct nw_layer *tap)
{
    tap->context = (void *)(intptr_t)fd;
    for (;;)
    {
        unsigned char buffer[1518];
        ssize_t nread = read(fd, &buffer, sizeof(buffer));
        if (nread < 0)
        {
            perror("Reading from TAP interface");
            close(fd);
            return -1;
        }
        struct nw_layer_data data =
        {
            .data = buffer,
            .len = (size_t)nread
        };

        tap->process_for_up(tap, &data);
    }
}

int send_to_ethernet(struct nw_layer *tap, struct nw_layer_data *data)
{
    tap->ups[0]->process_for_up(tap->ups[0], data);
    return 0;
}

int write_to_tap(struct nw_layer *tap, struct nw_layer_data *data)
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