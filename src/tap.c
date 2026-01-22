#include "tap.h"

int start_listening(int fd, struct nw_layer *tap)
{
    init_buffer_pool();
    for (;;)
    {
        struct pkt *packet = allocate_pkt();
        ssize_t nread = read(fd, packet->data, MAX_ETH_FRAME_SIZE);
        if (nread < 0)
            continue;

        packet->len = (size_t)nread;
        packet->offset = 0;

        pkt_result result = tap->rcv_up(tap, packet);
        printf("%d \n\n", result);
        if (result != SENT)
            release_pkt(packet);
    }
}

pkt_result send_up_to_ethernet(struct nw_layer *tap, struct pkt *packet)
{
    return tap->ups[0]->rcv_up(tap->ups[0], packet);
}

pkt_result write_to_tap(struct nw_layer *tap, struct pkt *packet)
{
    struct tap_context *tap_ctx = (struct tap_context *)tap->context;
    int fd = tap_ctx->fd;
    ssize_t nwrite = write(fd, packet->data, packet->len);

    if (nwrite < 0)
    {
        perror("Writing to TAP interface");
        close(fd);

        return WRITE_ERROR;
    }
/*
    FILE *log = fopen("out.txt", "a");
    if (log)
    {
        for (size_t i = 0; i < packet->len; i++)
            fprintf(log, "%02X", packet->data[i]);
        fprintf(log, "\n");
        fclose(log);
    }
*/
    release_pkt(packet);
    return SENT;
}