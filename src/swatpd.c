/*
 * swatp - stolen wifi aggregate tunneling protocol
 * copyright (c) 2011 j.a. roberts tunney
 * licensed under the gnu agpl 3 or later
 */

/**
 * @file swatpd.c
 * @brief stolen wifi aggregate tunneling protocol daemon
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <time.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <assert.h>
#include <stdbool.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <bits/sockaddr.h>
#include <linux/if.h>
#include <linux/if_tun.h>

#define max(a, b) (((a) > (b)) ? (a) : (b))
#define min(a, b) (((a) < (b)) ? (a) : (b))

typedef struct swat_header_s swat_header_t;

struct swat_header_s {
    uint32_t magic;
    uint32_t type;
    uint32_t seq;
};

static const int max_history = 512;
static bool is_running = true;

static inline bool empty(const char *s)
{
    return (!s || s[0] == '\0');
}

static inline bool strmatch(const char *s1, const char *s2)
{
    if (!s1 || !s2) {
        return false;
    } else {
        return (strcmp(s1, s2) == 0);
    }
}

static int tun_alloc(char *dev)
{
    struct ifreq ifr[1] = { 0 };
    ifr->ifr_flags = IFF_TUN;
    if (*dev)
        strncpy(ifr->ifr_name, dev, IFNAMSIZ);

    int fd;
    if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
        perror("open(/dev/net/tun) error");
        exit(1);
    }

    if (ioctl(fd, TUNSETIFF, (void *)ifr) < 0) {
        perror("ioctl(TUNSETIFF) error");
        exit(1);
    }

    strcpy(dev, ifr->ifr_name);

    if (ioctl(fd, TUNSETPERSIST, 0) < 0) {
        perror("ioctl(TUNSETPERSIST) error");
        exit(1);
    }

    return fd;
}

static void run(const char *fmt, ...)
{
    va_list ap;
    char buf[1024 * 16];
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    int rc = system(buf);
    if (WIFSIGNALED(rc) != 0) {
        fprintf(stderr, "command failed: %s\n", buf);
        exit(1);
    }
}

static int sockin(const char *ip, uint16_t port)
{
    int fd;
    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket(SOCK_DGRAM) failed");
        exit(1);
    }

    struct sockaddr_in sa[1] = { 0 };
    sa->sin_family = AF_INET;
    sa->sin_port = htons(port);
    sa->sin_addr.s_addr = inet_addr(ip);
    if (bind(fd, (struct sockaddr *)sa, sizeof(sa)) < 0) {
        perror("bind(SOCK_DGRAM) error");
        exit(1);
    }

    return fd;
}

/**
 * Returns IPv4 address associated with device name
 *
 * For example: get_device_ip4_addr("eth0") => "10.66.6.1"
 *
 * @param name  Name of network device.  For example "eth0"
 * @return      IP of device or NULL.  You need to free() this.
 */
static char *get_device_ip4_addr(const char *devname)
{
    if (empty(devname)) {
        return NULL;
    }

    int fd = -1;
    char *res = NULL;
    struct ifreq *ifr = NULL;
    struct ifconf ifc[1] = { 0 };

    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket(SOCK_DGRAM)");
        goto finish;
    }

    /* find number of network interfaces */
    ifc->ifc_ifcu.ifcu_req = NULL;
    ifc->ifc_len = 0;
    if (ioctl(fd, SIOCGIFCONF, ifc) < 0) {
        perror("ioctl(SIOCGIFCONF) #1");
        goto finish;
    }
    const int ifcnt = ifc->ifc_len / sizeof(struct ifreq);

    if ((ifr = malloc(ifc->ifc_len * 2)) == NULL) {
        goto finish;
    }

    /* request list all device names with their ips */
    ifc->ifc_ifcu.ifcu_req = ifr;
    if (ioctl(fd, SIOCGIFCONF, ifc) < 0) {
        perror("ioctl(SIOCGIFCONF) #2");
        goto finish;
    }

    int n;
    for (n = 0; n < ifcnt; n++) {
        const struct ifreq *r = &ifr[n];
        const struct sockaddr_in *sin = (struct sockaddr_in *)&r->ifr_addr;
        if (strmatch(r->ifr_name, devname)) {
            const char *ip = inet_ntoa(sin->sin_addr);
            if (!empty(ip)) {
                res = strdup(ip);
            }
            break;
        }
    }

finish:
    if (fd != -1) close(fd);
    if (ifr) free(ifr);
    return res;
}

/**
 * Creates a udp socket for sending ip traffic to remote endpoint
 *
 * The socket is connected to the remote endpoint so you can use
 * send() instead of sendto().
 *
 * @param dev   Required name of network device to use (e.g. eth0, wlan0)
 * @param ip    Required remote IP address or hostname
 * @param port  Required remote port number
 * @return      Socket file descriptor or crash
 */
static int sockout(const char *dev, const char *ip, uint16_t port)
{
    int fd;
    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket(SOCK_DGRAM) failed");
        exit(1);
    }

    struct sockaddr_in sa[1] = { 0 };
    sa->sin_family = AF_INET;
    sa->sin_port = htons(port);
    sa->sin_addr.s_addr = inet_addr(ip);
    if (connect(fd, (struct sockaddr *)sa, sizeof(sa)) < 0) {
        perror("connect(SOCK_DGRAM) error");
        exit(1);
    }

    /* i'm not sure if this actually works */
    struct ifreq ifr[1] = { 0 };
    snprintf(ifr->ifr_name, sizeof(ifr->ifr_name), "%s", dev);
    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
        perror("ioctl(SIOCGIFINDEX) error");
    }
    if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
                   (void *)ifr, sizeof(ifr)) < 0) {
        perror("setsockopt(SO_BINDTODEVICE) error");
    }

    return fd;
}

static void log_packet(const char *prefix, uint8_t *ippkt, size_t len)
{
    if (!ippkt || len < sizeof(struct ip)) {
        return;
    }
    struct ip *iphdr = (struct ip *)ippkt;
    char ip_src[INET_ADDRSTRLEN];
    char ip_dst[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(iphdr->ip_src), ip_src, sizeof(ip_src));
    inet_ntop(AF_INET, &(iphdr->ip_dst), ip_dst, sizeof(ip_dst));
    printf("%s %zd bytes: %s -> %s\n", prefix, len, ip_src, ip_dst);
}

/**
 * Easier way to generate a set of file descriptors for select()
 */
static int make_fd_set(fd_set *fds, int fd, ...)
{
    va_list ap;
    int maxfd = 0;
    int arg = fd;
    va_start(ap, fd);
    FD_ZERO(fds);
    do {
        assert(arg >= 0);
        FD_SET(arg, fds);
        if (arg > maxfd) {
            maxfd = arg;
        }
    } while ((arg = va_arg(ap, int)) != -1);
    va_end(ap);
    return maxfd;
}

static void on_close(int signum)
{
    is_running = false;
}

int main(int argc, const char *argv[])
{
    assert(argc >= 1 + 3 + 3);
    assert((argc - (1 + 3)) % 3 == 0);

    const char *linkaddr = argv[1];
    const char *listen_ip = argv[2];
    uint16_t listen_port = (uint16_t)atoi(argv[3]);

    char tundev[128] = { 0 };
    int tunfd = tun_alloc(tundev);
    run("ip link set %s up", tundev);
    run("ip link set %s mtu 1300", tundev);
    run("ip addr add %s dev %s", linkaddr, tundev);
    int skin = sockin(listen_ip, listen_port);

    int skouts[16] = {  -1, -1, -1, -1,   -1, -1, -1, -1,
                        -1, -1, -1, -1,   -1, -1, -1, -1  };
    int n = 0;
    int j = 4;
    while (j < argc && n < 16) {
        const char *dev = argv[j + 0];
        const char *ip = argv[j + 1];
        uint16_t port = (uint16_t)atoi(argv[j + 2]);
        skouts[n] = sockout(dev, ip, port);
        n += 1;
        j += 3;
    }

    uint32_t seq = 0; /* current sequence id for egress frames */
    int seenidx = 0;
    int64_t seen[max_history]; /* history of ingress seqs to drop duplicates */

    for (n = 0; n < max_history; n++) seen[n] = -1;

    /* for storing/receiving packets */
    uint8_t packet_memory[1024 * 64];

    /* buf alias for packet including swat header */
    uint8_t *pkt = packet_memory;
    swat_header_t *hdr = (swat_header_t *)pkt;
    const int maxamt = sizeof(packet_memory);

    /* pointer alias for ip packet (stuff after swat header) */
    uint8_t *ippkt = packet_memory + sizeof(swat_header_t);
    struct ip *iphdr = (struct ip *)ippkt;
    const int ipmaxamt = sizeof(packet_memory) - sizeof(swat_header_t);

    signal(SIGINT, on_close);
    while (is_running) {
        fd_set rfds[1];
        int maxfd = make_fd_set(rfds, tunfd, skin, -1);
        int rc = select(maxfd + 1, rfds, NULL, NULL, NULL);
        if (rc < 0) {
            if (errno == EINTR) {
                continue; /* a signal rudely interrupted us */
            }
            perror("select() failed");
            exit(1);
        }

        if (FD_ISSET(tunfd, rfds)) {
            /* data from our network, forward to remote endpoint */
            ssize_t ipamt = read(tunfd, ippkt, ipmaxamt);
            if (ipamt <= 0) {
                perror("read(tunfd) error");
                exit(1);
            }
            if (ipamt > sizeof(struct ip)) {
                log_packet(" egress", ippkt, ipamt);
                hdr->magic = htonl(0xFeedABee);
                hdr->type = htonl(0);
                hdr->seq = htonl(++seq);
                for (n = 0; n < 16 && skouts[n] >= 0; n++) {
                    write(skouts[n], pkt, sizeof(swat_header_t) + ipamt);
                }
            }
        }

        if (FD_ISSET(skin, rfds)) {
            /* data from remote endpoint, forward to our network */
            ssize_t amt = read(skin, pkt, maxamt);
            if (amt <= 0) {
                perror("read(skin) error");
                exit(1);
            }
            if (amt > sizeof(swat_header_t) + sizeof(struct ip)) {
                bool drop = false;
                int64_t rseq = (int64_t)ntohl(hdr->seq);
                for (n = 0; n < max_history; n++) {
                    if (rseq == seen[n]) {
                        drop = true;
                        break;
                    }
                }
                if (!drop) {
                    seen[seenidx] = rseq;
                    if (++seenidx == max_history) {
                        seenidx = 0;
                    }
                    const size_t ipamt = amt - sizeof(swat_header_t);
                    log_packet("ingress", ippkt, ipamt);
                    write(tunfd, ippkt, ipamt);
                }
            }
        }
    }

    fprintf(stderr, "shutting down\n");
    exit(0);
}

/* For Emacs:
 * Local Variables:
 * indent-tabs-mode:nil
 * c-basic-offset:4
 * c-file-style: nil
 * End:
 * For VIM:
 * vim:set softtabstop=8 shiftwidth=8 tabstop=8:
 */
