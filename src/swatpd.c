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

enum swatp_mode {
    reliable,
    fast
};

struct swatp {
    uint32_t magic;
    uint32_t type;
    uint32_t seq;
};

static const int history_max = 512;
static bool is_running = true;
static const int mtu = 1500 - sizeof(struct iphdr) - sizeof(struct udphdr) -
    sizeof(struct swatp);

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
    assert(dev);

    struct ifreq ifr[1] = {{{{ 0 }}}};
    ifr->ifr_flags = IFF_TUN;
    if (*dev) {
        strncpy(ifr->ifr_name, dev, IFNAMSIZ);
    }

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

    struct sockaddr_in sa[1] = {{ 0 }};
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
 * Creates a udp socket for sending ip traffic to remote endpoint
 *
 * The socket is "connected" to the remote endpoint so you can use
 * send() instead of sendto().
 *
 * We use Linux's SO_BINDTODEVICE feature to bind the socket to a
 * specific ethernet device.  This means our packets will skip the
 * routing table entirely and use arp to figure out the next ethernet
 * hop.
 *
 * This is important because once the tunnel is activated we'll change
 * the default route to the tunnel, so we don't want to tunnel our
 * tunnel traffic inside our tunnel dawg.
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

    struct sockaddr_in sa[1] = {{ 0 }};
    sa->sin_family = AF_INET;
    sa->sin_port = htons(port);
    sa->sin_addr.s_addr = inet_addr(ip);
    if (connect(fd, (struct sockaddr *)sa, sizeof(sa)) < 0) {
        perror("connect(SOCK_DGRAM) error");
        exit(1);
    }

    struct ifreq ifr[1] = {{{{ 0 }}}};
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
    if (!ippkt || len < sizeof(struct iphdr)) {
        return;
    }
    struct iphdr *iphdr = (struct iphdr *)ippkt;
    char ip_src[INET_ADDRSTRLEN];
    char ip_dst[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(iphdr->saddr) - 1, ip_src, sizeof(ip_src));
    inet_ntop(AF_INET, &(iphdr->daddr) - 1, ip_dst, sizeof(ip_dst));
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

static enum swatp_mode swatp_mode(const char *smode)
{
    if (strmatch(smode, "reliable")) {
        return reliable;
    } else if (strmatch(smode, "fast")) {
        return fast;
    } else {
        fprintf(stderr, "invalid mode: %s\n", smode);
        exit(1);
    }
}

int main(int argc, const char *argv[])
{
    assert(argc >= 1 + 4 + 3);
    assert((argc - (1 + 4)) % 3 == 0);

    const enum swatp_mode mode = swatp_mode(argv[1]);
    const char *linkaddr = argv[2];
    const char *listen_ip = argv[3];
    const uint16_t listen_port = (uint16_t)atoi(argv[4]);

    /* create tunnel device */
    char tundev[128] = { 0 };
    const int tunfd = tun_alloc(tundev);
    run("ip link set %s up", tundev);
    run("ip link set %s mtu %d", tundev, mtu);
    run("ip addr add %s dev %s", linkaddr, tundev);
    const int skin = sockin(listen_ip, listen_port);

    /* create array of transmit sockets */
    int j = 1 + 4;
    const int skouts_len = (argc - j) / 3;
    int skouts[skouts_len];
    int skouts_robin = 0; /* for fast mode */
    int n = 0;
    while (j < argc && n < 16) {
        const char *dev = argv[j + 0];
        const char *ip = argv[j + 1];
        const uint16_t port = (uint16_t)atoi(argv[j + 2]);
        skouts[n] = sockout(dev, ip, port);
        n += 1;
        j += 3;
    }

    uint32_t seq = 0; /* current sequence id for egress frames */
    int seenidx = 0;
    int64_t seen[history_max]; /* history of ingress seqs to drop duplicates */
    for (n = 0; n < history_max; n++) {
        seen[n] = -1;
    }

    uint8_t memory[1024 * 64];

    /* alias for packet including swat header */
    uint8_t *pkt = memory;
    struct swatp *hdr = (struct swatp *)pkt;
    const int maxamt = sizeof(memory);

    /* alias for ip packet (stuff after swat header) */
    uint8_t *ippkt = memory + sizeof(struct swatp);
    /* struct iphdr *iphdr = (struct iphdr *)ippkt; */
    const int ipmaxamt = sizeof(memory) - sizeof(struct swatp);

    signal(SIGINT, on_close);
    while (is_running) {
        fd_set rfds[1];
        int maxfd = make_fd_set(rfds, tunfd, skin, -1);
        int rc = select(maxfd + 1, rfds, NULL, NULL, NULL);
        if (rc < 0) {
            if (errno == EINTR) {
                continue; /* a signal rudely interrupted us */
            }
            perror("select() error");
            exit(1);
        }

        if (FD_ISSET(tunfd, rfds)) {
            /* data from our network, forward to remote endpoint */
            ssize_t ipamt = read(tunfd, ippkt, ipmaxamt);
            if (ipamt <= 0) {
                perror("read(tunfd) error");
                exit(1);
            }
            if (ipamt > sizeof(struct iphdr)) {
                log_packet(" egress", ippkt, ipamt);
                hdr->magic = htonl(0xFeedABee);
                hdr->type = htonl(0);
                hdr->seq = htonl(++seq);
                const int amt = sizeof(struct swatp) + ipamt;
                switch (mode) {
                case reliable:
                    for (n = 0; n < skouts_len; n++) {
                        if (write(skouts[n], pkt, amt) != amt) {
                            perror("write() error");
                        }
                    }
                    break;
                case fast:
                    if (write(skouts[skouts_robin], pkt, amt) != amt) {
                        perror("write() error");
                    }
                    skouts_robin += 1;
                    skouts_robin = skouts_robin % skouts_len;
                    break;
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
            if (amt > sizeof(struct swatp) + sizeof(struct iphdr)) {
                bool drop = false;
                const int64_t rseq = (int64_t)ntohl(hdr->seq);
                for (n = 0; n < history_max; n++) {
                    if (rseq == seen[n]) {
                        drop = true;
                        break;
                    }
                }
                if (!drop) {
                    seen[seenidx] = rseq;
                    if (++seenidx == history_max) {
                        seenidx = 0;
                    }
                    const size_t ipamt = amt - sizeof(struct swatp);
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
