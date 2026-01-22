#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include "stack_constructor.h"

#ifdef __linux__
#include <linux/if_tun.h>
#include <linux/rtnetlink.h>
#elif defined(__APPLE__) || defined(__MACH__)
#include <sys/socket.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>
#include <net/if_utun.h>
#define TUNSETIFF _IOW('T', 202, int)
#define IFF_TUN 0x0001
#define IFF_TAP 0x0002
#define IFF_NO_PI 0x1000
#define UTUN_CONTROL_NAME "com.apple.net.utun_control"
#endif

int tap_setup();
int get_tap(char *name, int flags);
int activate_tap(char *if_name);
int set_ipv4_addr(char *name, char *address);

const unsigned char IPV4_BROADCAST_MAC[MAC_ADDR_LEN] = {0xFF, 0xFF, 0xFF,
                                                        0xFF, 0xFF, 0xFF};
// TAP's IPV4 set to 192.168.100.1 by set_ipv4_addr()
// subnet mask defaulted to 255.255.255.0
// dummy must be on same subnet
const unsigned char DUMMY_IPV4[4] = {192, 168, 100, 2};
const unsigned char DUMMY_MAC_ADDR[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};

int main()
{
    int tap_fd;
    if ((tap_fd = tap_setup()) < 0)
        return 1;

    struct nw_layer *tap = construct_stack(tap_fd);
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
#ifdef __linux__
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
#elif defined(__APPLE__) || defined(__MACH__)
    // On macOS, try TAP first (if tuntaposx is installed), then fall back to utun (TUN)
    int fd;
    struct ctl_info ctl_info;
    struct sockaddr_ctl sc;
    
    // First, try to open /dev/tap0, /dev/tap1, etc. (if tuntaposx is installed)
    for (int i = 0; i < 10; i++)
    {
        char tap_path[32];
        snprintf(tap_path, sizeof(tap_path), "/dev/tap%d", i);
        fd = open(tap_path, O_RDWR);
        if (fd >= 0)
        {
            // Successfully opened TAP device
            snprintf(name, IFNAMSIZ, "tap%d", i);
            return fd;
        }
    }
    
    // If TAP devices not available, use built-in utun (TUN interface)
    // Note: utun is TUN (layer 3), not TAP (layer 2), but it's the best we can do
    fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (fd < 0)
    {
        perror("socket PF_SYSTEM");
        return fd;
    }
    
    memset(&ctl_info, 0, sizeof(ctl_info));
    strncpy(ctl_info.ctl_name, UTUN_CONTROL_NAME, sizeof(ctl_info.ctl_name));
    
    if (ioctl(fd, CTLIOCGINFO, &ctl_info) < 0)
    {
        perror("ioctl CTLIOCGINFO");
        close(fd);
        return -1;
    }
    
    memset(&sc, 0, sizeof(sc));
    sc.sc_id = ctl_info.ctl_id;
    sc.sc_len = sizeof(sc);
    sc.sc_family = AF_SYSTEM;
    sc.ss_sysaddr = AF_SYS_CONTROL;
    sc.sc_unit = 0; // Let the system assign a unit number
    
    if (connect(fd, (struct sockaddr *)&sc, sizeof(sc)) < 0)
    {
        if (errno == EPERM || errno == EACCES)
        {
            fprintf(stderr, "Error: Creating utun interface requires root privileges.\n");
            fprintf(stderr, "Please run with: sudo ./build/networking.elf\n");
        }
        perror("connect utun");
        close(fd);
        return -1;
    }
    
    // Get the interface name that was assigned
    socklen_t len = IFNAMSIZ;
    if (getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, name, &len) < 0)
    {
        perror("getsockopt UTUN_OPT_IFNAME");
        // Continue anyway, the interface should still work
        strncpy(name, "utun0", IFNAMSIZ);
    }
    
    return fd;
#else
    #error "Unsupported platform"
#endif
}