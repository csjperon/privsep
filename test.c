#include <sys/types.h>
#include <sys/socket.h>

#include <arpa/inet.h>

#include <netdb.h>
#include <stdio.h>
#include <err.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <fcntl.h>

#include "privsep.h"

void
test_getaddrinfo(void)
{
    struct addrinfo *result, *rp;
    struct addrinfo hints;
    char ipbuf[128];
    struct sockaddr_in *sa;
    struct sockaddr_in6 *sa6;
    int s;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_STREAM;
    s = privsep_getaddrinfo("www.fastly.com", "80", &hints, &result);
    if (s != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
        exit(EXIT_FAILURE);
    }
    for (rp = result; rp != NULL; rp = rp->ai_next) {
        bzero(ipbuf, sizeof(ipbuf));
        printf("%d\n", rp->ai_family);
        switch (rp->ai_family) {
        case PF_INET6:
            sa6 = (struct sockaddr_in6 *) rp->ai_addr;
            inet_ntop(rp->ai_family, (void *)&sa6->sin6_addr, ipbuf, rp->ai_addrlen);
            break;
        case PF_INET:
            sa = (struct sockaddr_in *) rp->ai_addr;
            inet_ntop(rp->ai_family, (void *)&sa->sin_addr, ipbuf, rp->ai_addrlen);
            break;
        }
        printf("%s\n", ipbuf);
    }
    privsep_freeaddrinfo(result);
}

int
main(int argc, char *argv [])
{
    privsep_t psd;
    FILE *fp;

    psd.user = strdup("vagrant");
    assert(psd.user != NULL);
    if (privsep_init(&psd) == -1) {
        err(1, "privsep_init failed");
    }
    privsep_bind_sandbox(SANDBOX_POLICY_H2OMAIN);
    privsep_sandbox_init();
    test_getaddrinfo();
    printf("continuing as non-privilged process\n");
    fp = privsep_fopen("/etc/passwd", "r");
    if (fp == NULL) {
        err(1, "failed");
    }
    assert(fp != NULL);
    printf("Recieved fp %p (fd %d) from privileged process\n",
        fp, fileno(fp));
    fclose(fp);
    int fd = privsep_open("/etc/passwd", O_RDONLY);
    if (fd == -1) {
        err(1, "privsep_open failed");
    }
    close(fd);
    printf("got FD %d\n", fd);
    privsep_cleanup(&psd);
    return (0);
}
