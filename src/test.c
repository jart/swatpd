
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main(int argc, const char *argv[])
{
    struct ifreq *ifr;
    struct ifconf ifc;
    int s, i;
    int numif;

    // find number of interfaces.
    memset(&ifc, 0, sizeof(ifc));
    ifc.ifc_ifcu.ifcu_req = NULL;
    ifc.ifc_len = 0;

    if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket");
        exit(1);
    }

    if (ioctl(s, SIOCGIFCONF, &ifc) < 0) {
        perror("ioctl");
        exit(2);
    }

    if ((ifr = malloc(ifc.ifc_len * 2)) == NULL) {
        perror("malloc");
        exit(3);
    }
    ifc.ifc_ifcu.ifcu_req = ifr;

    if (ioctl(s, SIOCGIFCONF, &ifc) < 0) {
        perror("ioctl2");
        exit(4);
    }
    close(s);

    numif = ifc.ifc_len / sizeof(struct ifreq);
    for (i = 0; i < numif; i++) {
        struct ifreq *r = &ifr[i];
        struct sockaddr_in *sin = (struct sockaddr_in *)&r->ifr_addr;
        printf("%-8s : %s\n", r->ifr_name, inet_ntoa(sin->sin_addr));
    }

    free(ifr);
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
