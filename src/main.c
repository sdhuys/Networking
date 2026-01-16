#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <linux/if_tun.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include "stack_constructor.h"

int tap_setup();
int get_tap(char *name, int flags);
int activate_tap(char *if_name);
int set_ipv4_addr(char *name, char *address);

int main()
{
    int tap_fd;
    if ((tap_fd = tap_setup()) < 0)
        return 1;

    struct nw_layer *tap = construct_stack();
    
    start_listening(tap_fd, tap);

    return 0;
}

int tap_setup()
{
    char tap_address[] = "192.168.100.1";
    char if_name[IFNAMSIZ] = "tap0";
    int tap_fd;
    if ((tap_fd = get_tap(if_name, IFF_TAP | IFF_NO_PI)) < 0)
    {
        perror("Getting TAP interace");
        return -1;
    }

    if (activate_tap(if_name) < 0)
    {
        perror("Activating TAP interface");
        close(tap_fd);
        return -1;
    }

    if (set_ipv4_addr(if_name, tap_address) < 0)
    {
        perror("Setting IPv4 address");
        close(tap_fd);
        return -1;
    }
    return tap_fd;
}

// Sets ipv4 address to 192.168.100.1
// Subnet mask defaults to 255.255.255.0 => ok for now
int set_ipv4_addr(char *name, char *address)
{
    int sock;
    struct ifreq ifr;
    struct sockaddr_in *addr;
    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        perror("socket");
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, name, IFNAMSIZ);

    addr = (struct sockaddr_in *)&ifr.ifr_addr;
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = inet_addr(address);

    if (ioctl(sock, SIOCSIFADDR, &ifr) < 0)
    {
        perror("ioctl SIOCSIFADDR");
        close(sock);
    }
    return 0;
}

int activate_tap(char *name)
{
    int sock;
    struct ifreq ifr;
    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        perror("socket");
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    strcpy(ifr.ifr_name, name);

    ifr.ifr_flags |= (IFF_UP | IFF_RUNNING);
    if (ioctl(sock, SIOCSIFFLAGS, &ifr) < 0)
    {
        perror("ioctl SIOCSIFFLAGS");
        close(sock);
        return -1;
    }
    close(sock);
    return 0;
}

int get_tap(char *name, int flags)
{
    struct ifreq ifr;
    int fd, error;

    if ((fd = open("/dev/net/tun", O_RDWR)) < 0)
    {
        perror("open /dev/net/tun");
        return fd;
    }
    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = flags;

    if (name)
        strncpy(ifr.ifr_name, name, IFNAMSIZ);

    if ((error = ioctl(fd, TUNSETIFF, &ifr)) < 0)
    {
        perror("ioctl TUNSETIFF");
        close(fd);
        return error;
    }
    strcpy(name, ifr.ifr_name);
    return fd;
}