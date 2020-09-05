/*
 * Copyright (c) 2020 Christian S.J. Peron
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#include <sys/uio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <netdb.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <unistd.h>
#include <libgen.h>
#include <err.h>
#include <stdlib.h>

#include "privsep.h"
#include "privsep_sandbox_linux.h"

static pthread_key_t privsep_key;
static int privsep_initialized;

void privsep_sandbox_init(void)
{

    assert(privsep_initialized == 0);
    if (pthread_key_create(&privsep_key, free) != 0) {
        err(1, "pthread_key_create failed");
    }
    privsep_initialized = 1;
}

static privsep_thread_specific_t *get_tsd(void)
{
    privsep_thread_specific_t *tsd;
    struct sockaddr_un sun;
    int ret;

    printf("%s: enter\n", __func__);
    tsd = pthread_getspecific(privsep_key);
    if (tsd) {
        printf("returning tsd (%d)\n", tsd->sock);
        return (tsd);
    }
    printf("allocating tsd and pinning to this thread\n");
    tsd = calloc(1, sizeof(*tsd));
    if (tsd == NULL) {
        return (NULL);
    }
    tsd->sock = socket(PF_UNIX, SOCK_STREAM, 0);
    if (tsd->sock == -1) {
        /*
         * If we fail to get privsep socket, bail. Something has gone very
         * wrong and nothing will be able to facilitate whatever privilege
         * we are requesting.
         */
        abort();
    }
    printf("tsd sock %d\n", tsd->sock);
    bzero(&sun, sizeof(sun));
    sun.sun_family = PF_UNIX;
    snprintf(sun.sun_path, sizeof(sun.sun_path), "%s", privsep_get_sockpath());
    while (1) {
        printf("Connecting socket %s\n", sun.sun_path);
        ret = connect(tsd->sock, (struct sockaddr *)&sun, sizeof(sun));
        if (ret == -1 && errno == EINTR) {
            continue;
        } else if (ret == -1) {
            abort();
        }
        break;
    }
    printf("connected!\n");
    if (pthread_setspecific(privsep_key, tsd) != 0) {
        free(tsd);
        close(tsd->sock);
    }
    assert(tsd->sock != 0);
    printf("returning tsd with fd %d\n", tsd->sock);
    return (tsd);
}

/*
 * This function was largely lifted from FreeBSD which distributes
 * this file/function under the BSD-3-Clause license.
 */
static int privsep_mode_to_flags(const char *mode, int *flagsptr)
{
    int m, o, known;

    switch (*mode++) {
    case 'r':   /* open for reading */
        m = O_RDONLY;
        o = 0;
        break;
    case 'w':   /* open for writing */
        m = O_WRONLY;
        o = O_CREAT | O_TRUNC;
        break;
    case 'a':   /* open for appending */
        m = O_WRONLY;
        o = O_CREAT | O_APPEND;
        break;
    default:    /* illegal mode */
        errno = EINVAL;
        return (-1);
    }
    do {
        known = 1;
        switch (*mode++) {
        case 'b':
            /* 'b' (binary) is ignored */
            break;
        case '+':
            m = O_RDWR;
            break;
        case 'x':
            /* 'x' means exclusive (fail if the file exists) */
            o |= O_EXCL;
            break;
#ifdef O_CLOEXEC
        case 'e':
            /* set close-on-exec */
            o |= O_CLOEXEC;
            break;
#endif
        default:
            known = 0;
            break;
        }
    } while (known);
    if ((o & O_EXCL) != 0 && m == O_RDONLY) {
        errno = EINVAL;
        return (-1);
    }
    *flagsptr = m | o;
    return (0);
}

FILE *privsep_fopen(const char * restrict path, const char * restrict mode)
{
    int flags, fd;
    FILE *fp;

    if (privsep_mode_to_flags(mode, &flags)) {
        return (NULL);
    }
    fd = privsep_open(path, flags);
    if (fd == -1) {
        return (NULL);
    }
    fp = fdopen(fd, mode);
    return (fp);
}

static struct tm *privsep_dotime_r(const time_t *clock,
  struct tm *result, int type)
{
    char tzbuf[2048];
    privsep_thread_specific_t *psd;
    int time_type;
    uint32_t cmd;

    time_type = type;
    assert(time_type == PRIV_LOCALTIME || time_type == PRIV_GMTIME);
    psd = get_tsd();
    assert(psd != NULL);
    cmd = PRIV_GMTIME;
    privsep_must_write(psd->sock, &cmd, sizeof(cmd));
    privsep_must_write(psd->sock, &time_type, sizeof(time_type));
    privsep_must_write(psd->sock, (void *)clock, sizeof(*clock));
    privsep_must_read(psd->sock, tzbuf, sizeof(tzbuf));
    privsep_must_read(psd->sock, result, sizeof(*result));
    /*
     * NB: we need to figure out how important the timezone is and
     * determine how we want to manage the storage. Possibly thread
     * stack?.
     */
    return (result);
}

struct tm *privsep_gmtime_r(const time_t *clock, struct tm *result)
{

    return (privsep_dotime_r(clock, result, PRIV_GMTIME));
}

struct tm *privsep_localtime_r(const time_t *clock, struct tm *result)
{

    return (privsep_dotime_r(clock, result, PRIV_LOCALTIME));
}

pid_t privsep_waitpid(pid_t pid, int *status, int options)
{
    privsep_waitpid_t args;
    privsep_thread_specific_t *psd;
    uint32_t cmd;
    pid_t ret_pid;
    int ecode;

    psd = get_tsd();
    assert(psd != NULL);
    cmd = PRIV_WAITPID;
    privsep_must_write(psd->sock, &cmd, sizeof(cmd));
    args.pid = pid;
    args.options = options;
    privsep_must_write(psd->sock, &args, sizeof(args));
    privsep_must_read(psd->sock, &ret_pid, sizeof(ret_pid));
    privsep_must_read(psd->sock, &ecode, sizeof(ecode));
    privsep_must_read(psd->sock, status, sizeof(int));
    if (ecode != 0) {
        errno = ecode;
    }
    return (ret_pid);
}

ssize_t privsep_sendmsg(int sock, struct msghdr *msg, int flags)
{
    privsep_sendmsg_t args;
    struct iovec *iovp;
    privsep_thread_specific_t *psd;
    int ecode, index;
    uint32_t cmd;
    ssize_t cc;

    psd = get_tsd();
    assert(psd != NULL);
    cmd = PRIV_SENDMSG;
    privsep_must_write(psd->sock, &cmd, sizeof(cmd));
    /*
     * NB: this is very inefficient. We need to implement a file descriptor
     * cache in he privileged process so we aren't transmitted the fd
     * everytime we want to send an H3 packet.
     */
    privsep_send_fd(psd->sock, sock);
    args.msg_namelen = msg->msg_namelen;
    args.msg_iovlen = msg->msg_iovlen;
    args.msg_controllen = msg->msg_controllen;
    args.flags = flags;
    privsep_must_write(psd->sock, &args, sizeof(args));
    for (index = 0; index < msg->msg_iovlen; index++) {
        iovp = &msg->msg_iov[index];
        privsep_must_write(psd->sock, &iovp->iov_len, sizeof(iovp->iov_len));
        privsep_must_write(psd->sock, iovp->iov_base, iovp->iov_len);
    }
    privsep_must_write(psd->sock, msg->msg_name, args.msg_namelen);
    privsep_must_read(psd->sock, &ecode, sizeof(ecode));
    if (ecode != 0) {
        errno = ecode;
        return (-1);
    }
    privsep_must_write(psd->sock, msg->msg_control, args.msg_controllen);
    privsep_must_read(psd->sock, &ecode, sizeof(ecode));
    if (ecode != 0) {
        errno = ecode;
        return (-1);
    }
    privsep_must_read(psd->sock, &cc, sizeof(cc));
    privsep_must_read(psd->sock, &ecode, sizeof(ecode));
    return (cc);
}

void privsep_bind_sandbox(int policy)
{
    /*
     * SANDBOX_POLICY_BASIC is used to set a minimal sandbox policy on a
     * process. This process will not be using privsep, in which case 
     * skip the call to drop privs (which assumes the full privsep model
     * is being used.
     */
    switch (policy) {
    case SANDBOX_POLICY_NONE:
        return;
        break;
    case SANDBOX_POLICY_NEVERBLEED:
        break;
    case SANDBOX_POLICY_H2OMAIN:
#ifdef __linux__
        sandbox_bind(policy);
#endif
        break;
    }
}

int privsep_open(const char *path, int flags, ...)
{
    privsep_open_t oa;
    privsep_thread_specific_t *psd;
    int cmd, fd, ecode;

    printf("%s: enter\n", __func__);
    psd = get_tsd();
    printf("%s: using file descriptor %d\n", __func__, psd->sock);
    assert(psd != NULL);
    snprintf(oa.path, sizeof(oa.path), "%s", path);
    oa.flags = flags;
    cmd = PRIV_OPEN;
    printf("sending cmd\n");
    privsep_must_write(psd->sock, &cmd, sizeof(cmd));
    printf("sending args\n");
    privsep_must_write(psd->sock, &oa, sizeof(oa));
    privsep_must_read(psd->sock, &ecode, sizeof(ecode));
    if (ecode != 0) {
        errno = ecode;
        return (-1);
    }
    fd = privsep_receive_fd(psd->sock);
    return (fd);
}

static struct addrinfo *addrinfo_copy(privsep_getaddrinfo_result_t *ent)
{
    struct addrinfo *cres;

    cres = malloc(sizeof(*cres));
    if (cres == NULL)
        return (NULL);
    cres->ai_flags = ent->ai_flags;
    cres->ai_family = ent->ai_family;
    cres->ai_socktype = ent->ai_socktype;
    cres->ai_protocol = ent->ai_protocol;
    cres->ai_addrlen = ent->ai_addrlen;
    cres->ai_addr = malloc(cres->ai_addrlen);
    memcpy(cres->ai_addr, &ent->sas, cres->ai_addrlen);
    cres->ai_canonname = strdup(ent->ai_canonname);
    if (cres->ai_canonname == NULL) {
        free(cres);
        return (NULL);
    }
    return (cres);
}

static int process_getaddr_data(privsep_getaddrinfo_result_t *vec,
  size_t blen, struct addrinfo **res)
{
    privsep_getaddrinfo_result_t *ent;
    struct addrinfo *cres, *head;
    int nitems;

    if (blen % sizeof(*ent) != 0) {
        return (-1);
    }
    head = NULL;
    nitems = blen / sizeof(*ent);
    for (ent = &vec[0]; ent < &vec[nitems]; ent++) {
        cres = addrinfo_copy(ent);
        if (cres == NULL) {
            return (-1);
        }
        cres->ai_next = head;
        head = cres;
    }
    *res = head;
    return (0);
}

void privsep_freeaddrinfo(struct addrinfo *ai)
{

    assert(ai != NULL);
    free(ai->ai_addr);
    free(ai->ai_canonname);
    free(ai);
}

int privsep_getaddrinfo(const char *hostname, const char *servname,
  const struct addrinfo *hints, struct addrinfo **res)
{
    privsep_getaddrinfo_result_t *vec;
    privsep_getaddrinfo_t ga_args;
    privsep_thread_specific_t *psd;
    int cmd, ret;
    size_t blen;
 
    psd = get_tsd();
    assert(psd != NULL);
    memset(&ga_args, 0, sizeof(ga_args));
    snprintf(ga_args.hostname, sizeof(ga_args.hostname), "%s", hostname);
    snprintf(ga_args.servname, sizeof(ga_args.servname), "%s", servname);
    memcpy(&ga_args.hints, hints, sizeof(ga_args.hints));
    cmd = PRIV_GETADDRINFO;
    privsep_must_write(psd->sock, &cmd, sizeof(cmd));
    privsep_must_write(psd->sock, &ga_args, sizeof(ga_args));
	privsep_must_read(psd->sock, &ret, sizeof(cmd));
    if (ret != 0) {
        return (ret);
    }
    privsep_must_read(psd->sock, &blen, sizeof(blen));
    if (blen == -1) {
        return (EAI_MEMORY);
    }
    vec = malloc(blen);
    if (vec == NULL) {
        return (EAI_MEMORY);
    }
    privsep_must_read(psd->sock, vec, blen);
    ret = process_getaddr_data(vec, blen, res);
    free(vec);
    if (ret == -1) {
        return (EAI_MEMORY);
    }
    return (0);
}
