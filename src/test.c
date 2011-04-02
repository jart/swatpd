
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

/* struct sockaddr_in raddr[1]; */
/* socklen_t addrlen = sizeof(raddr); */
/* const ssize_t amt = recvfrom( */
/*     skin, pkt, maxamt, 0, (struct sockaddr *)raddr, &addrlen); */
/* const ssize_t tunamt = amt - sizeof(struct swatp); */

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

/**
 * Returns IPv4 address associated with device name
 *
 * For example: get_device_ip4_addr("eth0") => "10.66.6.1"
 *
 * @param name  Name of network device.  For example "eth0"
 * @return      IP of device or NULL.  You need to free() this.
 */
static int get_device_ip4_addr(const char *devname, char *ip, size_t ipamt)
{
    if (empty(devname) || ip == NULL || ipamt < INET_ADDRSTRLEN) {
        return -1;
    }

    int fd = -1;
    int res = -1;
    struct ifreq *ifr = NULL;
    struct ifconf ifc[1] = {{ 0 }};

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
            inet_ntop(AF_INET, &(sin->sin_addr), ip, ipamt);
            res = 0;
            break;
        }
    }

finish:
    if (fd != -1) { close(fd); }
    if (ifr) { free(ifr); }
    return res;
}

static int sockin(const char *dev, uint16_t port)
{
    int fd;
    /* if ((fd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)) < 0) { */
    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    /* if ((fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) { */
        perror("socket(SOCK_DGRAM) failed");
        exit(1);
    }

    char ip[INET_ADDRSTRLEN];
    if (get_device_ip4_addr(dev, ip, sizeof(ip)) < 0) {
        fprintf(stderr, "device '%s' doesn't have an ip4 address\n", dev);
        exit(1);
    }

    printf("bind %s %s %d\n", dev, ip, port);

    snprintf(ip, sizeof(ip), "0.0.0.0");

    {
        struct sockaddr_in sa[1] = {{ 0 }};
        sa->sin_family = AF_INET;
        sa->sin_port = htons(port);
        if (inet_pton(AF_INET, ip, &(sa->sin_addr)) < 0) {
            perror("bad connect address");
            exit(1);
        }
        if (bind(fd, (struct sockaddr *)sa, sizeof(sa)) < 0) {
            perror("bind(SOCK_DGRAM) error");
            exit(1);
        }
    }

    /* struct ifreq ifr[1] = {{{{ 0 }}}}; */
    /* snprintf(ifr->ifr_name, sizeof(ifr->ifr_name), "%s", dev); */
    /* if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) { */
    /*     perror("ioctl(SIOCGIFINDEX) error"); */
    /* } else { */
    /*     if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, */
    /*                    (void *)ifr, sizeof(ifr)) < 0) { */
    /*         perror("setsockopt(SO_BINDTODEVICE) error"); */
    /*     } */
    /* } */

    /* { */
    /*     struct sockaddr_in sa[1] = {{ 0 }}; */
    /*     sa->sin_family = AF_INET; */
    /*     sa->sin_port = htons(port); */
    /*     if (inet_pton(AF_INET, "66.55.144.147", &(sa->sin_addr)) < 0) { */
    /*         perror("bad connect address"); */
    /*         exit(1); */
    /*     } */
    /*     if (connect(fd, (struct sockaddr *)sa, sizeof(sa)) < 0) { */
    /*         perror("bind(SOCK_DGRAM) error"); */
    /*         exit(1); */
    /*     } */
    /* } */

    printf("connected\n");

    return fd;
}

int main(int argc, const char *argv[])
{
    {
        const char *dev = "eth0";
        char ip[INET_ADDRSTRLEN];
        assert(get_device_ip4_addr(dev, ip, INET_ADDRSTRLEN) == 0);
        printf("%s = %s\n", dev, ip);
    }
    {
        const char *dev = "wlan0";
        char ip[INET_ADDRSTRLEN];
        assert(get_device_ip4_addr(dev, ip, INET_ADDRSTRLEN) == 0);
        printf("%s = %s\n", dev, ip);
    }
    {
        const char *dev = "wlan1";
        char ip[INET_ADDRSTRLEN];
        assert(get_device_ip4_addr(dev, ip, INET_ADDRSTRLEN) == 0);
        printf("%s = %s\n", dev, ip);
    }

    {
        int fd = sockin("wlan0", 11443);
        /* write(fd, "hello", 5); */
        char buf[1024 * 64];
        int amt = read(fd, buf, sizeof(buf));
        int hlen = sizeof(struct iphdr) + sizeof(struct udphdr);
        hlen = 0;
        printf("got: %.*s\n", amt - hlen, buf + hlen);
        close(fd);
    }

    printf("\n");

    {
        int fd = sockin("wlan1", 11443);
        /* write(fd, "hello", 5); */
        char buf[1024 * 64];
        int amt = read(fd, buf, sizeof(buf));
        int hlen = sizeof(struct iphdr) + sizeof(struct udphdr);
        hlen = 0;
        printf("got: %.*s\n", amt - hlen, buf + hlen);
        close(fd);
    }

    return 0;
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
