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
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/wait.h>
#include <sys/un.h>

#include <netdb.h>
#include <err.h>
#include <stdio.h>
#include <grp.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <fcntl.h>
#include <pwd.h>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>

#include "privsep.h"

int privsep_flags;
static char *privsep_sock_path;

char *privsep_get_sockpath(void)
{

    return (privsep_sock_path);
}

static void privsep_set_sockpath(const char *path)
{

    assert(path != NULL);
    privsep_sock_path = strdup(path);
}

static void privsep_handle_dotime_r(privsep_worker_t *pswd)
{
    char tzbuf[2048];
    time_t clock;
    struct tm gmt;
    int type, valid;

    bzero(tzbuf, sizeof(tzbuf));
    privsep_must_read(pswd->sock, &type, sizeof(type));
    privsep_must_read(pswd->sock, &clock, sizeof(clock));
    valid = 0;
    switch (type) {
    case PRIV_GMTIME:
        gmtime_r(&clock, &gmt);
        valid = 1;
        break;
    case PRIV_LOCALTIME:
        localtime_r(&clock, &gmt);
        valid = 1;
        break;
    default:
        warnx("%s: invalid type time specified", __func__);
        bzero(&gmt, sizeof(gmt));
        bzero(tzbuf, sizeof(tzbuf));
        valid = 0;
    }
    if (valid) {
        snprintf(tzbuf, sizeof(tzbuf), "%s", gmt.tm_zone);
    }
    privsep_must_write(pswd->sock, tzbuf, sizeof(tzbuf));
    gmt.tm_zone = NULL;
    privsep_must_write(pswd->sock, &gmt, sizeof(gmt));
}

static void privsep_handle_waitpid(privsep_worker_t *pswd)
{
    privsep_waitpid_t args;
    int status, ecode;
    pid_t pid;

    privsep_must_read(pswd->sock, &args, sizeof(args));
    while (1) {
        status = 0;
        pid = waitpid(args.pid, &status, args.options);
        if (pid == -1 && errno == EINTR) {
            continue;
        }
        privsep_must_write(pswd->sock, &pid, sizeof(pid));
        ecode = errno;
        privsep_must_write(pswd->sock, &ecode, sizeof(ecode));
        privsep_must_write(pswd->sock, &status, sizeof(status));
        return;
    }
}

static void privsep_msghdr_cleanup(struct msghdr *msg)
{
    struct iovec *iovp;
    int index;

    assert(msg != NULL);
    for (index = 0; index < msg->msg_iovlen; index++) {
        iovp = &msg->msg_iov[index];
        free(iovp->iov_base);
    }
    free(msg->msg_iov);
    free(msg->msg_name);
    free(msg->msg_control);
}

static void privsep_handle_sendmsg(privsep_worker_t *pswd)
{
    privsep_sendmsg_t args;
    int sock, ecode, index;
    struct iovec *iovp;
    struct msghdr msg;
    ssize_t cc;

    bzero(&msg, sizeof(msg));
    sock = privsep_receive_fd(pswd->sock);
    privsep_must_read(pswd->sock, &args, sizeof(args));
    msg.msg_namelen = args.msg_namelen;
    msg.msg_controllen = args.msg_controllen;
    msg.msg_iovlen = args.msg_iovlen;
    msg.msg_iov = calloc(msg.msg_iovlen, sizeof(*iovp));
    /* NB: XXX send ecode */
    for (index = 0; index < msg.msg_iovlen; index++) {
        iovp = &msg.msg_iov[index];
        privsep_must_read(pswd->sock, &iovp->iov_len, sizeof(iovp->iov_len));
        iovp->iov_base = calloc(1, iovp->iov_len);
        privsep_must_read(pswd->sock, iovp->iov_base, iovp->iov_len);
    }
    /*
     * msg.msg_flags is not used by sendmsg(2). We can just leave it as zero.
     */
    msg.msg_name = calloc(1, args.msg_namelen);
    if (msg.msg_name == NULL) {
        ecode = errno;
        privsep_must_write(pswd->sock, &ecode, sizeof(ecode));
        close(sock);
        return;
    }
    privsep_must_read(pswd->sock, msg.msg_name, args.msg_namelen);
    ecode = 0;
    privsep_must_write(pswd->sock, &ecode, sizeof(ecode));
    msg.msg_control = calloc(1, args.msg_controllen);
    if (msg.msg_name == NULL) {
        ecode = errno;
        privsep_must_write(pswd->sock, &ecode, sizeof(ecode));
        close(sock);
        return;
    }
    privsep_must_read(pswd->sock, msg.msg_control, args.msg_controllen);
    ecode = 0;
    privsep_must_write(pswd->sock, &ecode, sizeof(ecode));
    cc = sendmsg(sock, &msg, args.flags);
    privsep_must_write(pswd->sock, &cc, sizeof(cc));
    if (cc == -1) {
        ecode = errno;
        privsep_must_write(pswd->sock, &ecode, sizeof(ecode));
        close(sock);
    }
    ecode = 0;
    privsep_must_write(pswd->sock, &ecode, sizeof(ecode));
    privsep_msghdr_cleanup(&msg);
    close(sock);
}

static void privsep_handle_getaddrinfo(privsep_worker_t *pswd)
{
    privsep_getaddrinfo_result_t *ent, *vec;
    size_t vec_used, vec_alloc, curlen;
    privsep_getaddrinfo_t ga_args;
    struct addrinfo *res, *res0;
    int error, sock, ret;

    sock = pswd->sock;
    privsep_must_read(sock, &ga_args, sizeof(ga_args));
    ret = getaddrinfo(ga_args.hostname, ga_args.servname, &ga_args.hints,
      &res0);
    if (ret != 0) {
        warnx("[PRIVSEP]: getaddr failed: %s\n", gai_strerror(ret));
    }
    vec_used = 0;
    vec_alloc = 0;
    vec = NULL;
    for (res = res0; res; res = res->ai_next) {
        if (vec == NULL) {
            vec_alloc = sizeof(*ent);
            vec = calloc(1, vec_alloc);
            if (vec == NULL) {
                error = -1;
                privsep_must_write(sock, &error, sizeof(error));
                return;
            }
        } else {
            vec_alloc = vec_alloc + sizeof(*ent);
            vec = realloc(vec,vec_alloc);
            if (vec == NULL) {
                error = -1;
                privsep_must_write(sock, &error, sizeof(error));
                return;
            }
        }
        ent = &vec[vec_used++];
        ent->ai_flags = res->ai_flags;
        ent->ai_family = res->ai_family;
        ent->ai_socktype = res->ai_socktype;
        ent->ai_protocol = res->ai_protocol;
        ent->ai_addrlen = res->ai_addrlen;
        memcpy(&ent->sas, res->ai_addr, res->ai_addrlen);
        if (res->ai_canonname != NULL) {
            snprintf(ent->ai_canonname, sizeof(ent->ai_canonname),
              "%s", res->ai_canonname);
        } else {
            ent->ai_canonname[0] = '\0';
        }
    }
    /* report success/failure */
    privsep_must_write(sock, &ret, sizeof(ret));
    if (ret != 0) {
        return;
    }
    curlen = vec_used * sizeof(*ent);
    if (curlen == 0) {
        curlen = -1;
        privsep_must_write(sock, &curlen, sizeof(curlen));
        return;
    }
    privsep_must_write(sock, &curlen, sizeof(curlen));
    privsep_must_write(sock, vec, curlen);
    free(vec);
}

static void privsep_handle_open(privsep_worker_t *pswd)
{
    privsep_open_t args;
    int ecode, fd;

    /*
     * NB: implement path based access control check
     */
    privsep_must_read(pswd->sock, &args, sizeof(args));
    fd = open(args.path, args.flags, args.mode);
    if (fd == -1) {
        ecode = errno;
        privsep_must_write(pswd->sock, &ecode, sizeof(ecode));
        return;
    }
    ecode = 0;
    privsep_must_write(pswd->sock, &ecode, sizeof(ecode));
    privsep_send_fd(pswd->sock, fd);
    close(fd);
}

static void *privsep_handle_requests(void *arg)
{
    privsep_worker_t *pswd;
    uint32_t cmd;

    pswd = (privsep_worker_t *) arg;
    while (1) {
        if (privsep_may_read(pswd->sock, &cmd, sizeof(cmd))) {
            break;
        }
        switch (cmd) {
        case PRIV_LOCALTIME:
        case PRIV_GMTIME:
            privsep_handle_dotime_r(pswd);
            break;
        case PRIV_WAITPID:
            privsep_handle_waitpid(pswd);
            break;
        case PRIV_SENDMSG:
            privsep_handle_sendmsg(pswd);
            break;
        case PRIV_GETADDRINFO:
            privsep_handle_getaddrinfo(pswd);
            break;
        case PRIV_OPEN:
            privsep_handle_open(pswd);
            break;
        default:
            err(1,"invalid command over privsep socket %d", cmd);
            break;
        }
    }
    close(pswd->sock);
    free(pswd);
    return (NULL);
}

static void *privsep_handle_accept(void *arg)
{
    privsep_listener_t *psl;
    privsep_worker_t *pswp;
    int nsock;

    printf("%s: entering accept loop\n", __func__);
    psl = (privsep_listener_t *)arg;
    while (1) {
        printf("accepting connections\n");
        nsock = accept(psl->sock, NULL, NULL);
        if (nsock == -1 && (errno == EINTR || errno == EAGAIN)) {
            continue;
        } else if (nsock == -1) {
            err(1, "[privsep] accept failed");
        }
        printf("accepted fd %d\n", nsock);
        pswp = calloc(1, sizeof(*pswp));
        if (pswp == NULL) {
            err(1, "[privsep] failed to allocate memory");
        }
        pswp->sock = nsock;
        if (pthread_create(&pswp->thr, NULL,
          privsep_handle_requests, pswp) != 0) {
            err(1, "[privsep] pthread create worker");
        }
    }
    return (NULL);
}

static void privsep_event_loop(int sock)
{
    privsep_listener_t *psl;
    pthread_t thr;
    void *ptr;

    printf("%s: enter\n", __func__);
    psl = calloc(1, sizeof(*psl));
    if (psl == NULL) {
        err(1, "calloc failed");
    }
    psl->sock = sock;
    printf("Creating accept thread\n");
    if (pthread_create(&thr, NULL, privsep_handle_accept, psl) != 0) {
        err(1, "[privsep] failed to launch accept thread");
    }
    if (pthread_join(thr, &ptr) != 0) {
        err(1, "pthread_hoin failed");
    }
}

static int privsep_setup_socket(privsep_t *psd)
{
    char sock_path[MAXPATHLEN], sock_dir[MAXPATHLEN], *buf;
    struct passwd *pwd, pwbuf;
    struct sockaddr_un sun;
    int sock, alloc;
    struct stat sb;

    if (stat("/etc/passwd", &sb) == -1) {
        err(1, "passwd database not accessible");
    }
    if (sb.st_size == 0) {
        err(1, "invalid passwd database");
    }
    alloc = 3 * sb.st_size;
    buf = malloc(alloc);
    if (buf == NULL) {
        err(1, "failed to allocate buffer");
    }
    if (getpwnam_r(psd->user, &pwbuf, buf, alloc, &pwd) != 0) {
        err(1,  "[privsep] user %s does not exist", psd->user);
    }
    if (snprintf(sock_dir, MAXPATHLEN, "/tmp/h2o_privsep.XXXXXX") < 0) {
        err(1, "snprintf failed");
    }
    if (mkdtemp(sock_dir) == NULL) {
        err(1, "mkdtemp failed");
    }
    if (chown(sock_dir, pwd->pw_uid, pwd->pw_gid) == -1) {
        err(1, "[privsep] chown failed");
    }
    free(buf);
    sock = socket(PF_UNIX, SOCK_STREAM, 0);
    if (sock == -1) {
        err(1, "[privsep] socket failed");
    }
    snprintf(sock_path, sizeof(sock_path), "%s/_", sock_dir);
    bzero(&sun, sizeof(sun));
    sun.sun_family = PF_UNIX;
    bcopy(sock_path, sun.sun_path, strlen(sock_path));
    (void) unlink(sock_path);
    if (bind(sock, (struct sockaddr *)&sun, sizeof(sun)) == -1) {
        err(1, "[privsep] bind failed");
    }
    if (listen(sock, SOMAXCONN) == -1) {
        err(1, "[privsep] listen failed");
    }
    if (chown(sock_path, pwd->pw_uid, pwd->pw_gid) == -1) {
        err(1, "[privsep] chown failed");
    }
    privsep_set_sockpath(sock_path);
    return (sock);
}

int privsep_init(privsep_t *psd)
{
    int sock;
    pid_t pid;

    sock = privsep_setup_socket(psd);
    privsep_flags |= PRIVSEP_NON_PRIVILEGED;
    pid = fork();
    if (pid == -1) {
        err(1, "fork of privileged process failed");
    }
    if (pid == 0) {
        privsep_flags &= ~PRIVSEP_NON_PRIVILEGED;
        privsep_flags |= PRIVSEP_PRIVILEGED;
        privsep_event_loop(sock);
        printf("privsep event loop exiting\n");
        _exit(0);
    }
    printf("privsep (privileged) process forked pid: %d\n", pid);
    return (0);
}
