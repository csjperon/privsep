#include <sys/types.h>
#include <sys/socket.h>

#include <netdb.h>
#include <stdio.h>
#include <err.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

#include "privsep.h"

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
    printf("continuing as non-privilged process\n");
    fp = privsep_fopen("/etc/passwd", "r");
    if (fp == NULL) {
        err(1, "failed");
    }
    assert(fp != NULL);
    printf("Recieved fp %p (fd %d) from privileged process\n",
        fp, fileno(fp));
    pause();
    return (0);
}
