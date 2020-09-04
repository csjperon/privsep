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

#include <sys/uio.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <netdb.h>
#include <unistd.h>
#include <stdlib.h>
#include <libgen.h>
#include <err.h>
#include <assert.h>

#include "privsep.h"

char *privsep_marshal_vec(char *const vec[], size_t *mlen)
{
    size_t totlen, slen, count, k;
    char *const *copy;
    char *bp, *buf;

    copy = vec;
    count = 0;
    totlen = 0;
    /*
     * Iterate through array/vector to count the number of strings, but also
     * to keep track of the size for each string.
     */
    while ((bp = *copy++)) {
        totlen += strlen(bp);
        count++;
    }
    totlen += count;    /* \0 delimeter for each string */
    totlen += 1;        /* \0 terminating \0 */
    buf = malloc(totlen);
    if (buf == NULL) {
        return (NULL);
    }
    *mlen = totlen;
    bp = buf;
    for (k = 0; k < count; k++) {
        slen = strlen(vec[k]);
        bcopy(vec[k], bp, slen);
        bp += slen;
        *bp++ = '\0';
    }
    *bp = '\0';
    return (buf);
}

char **privsep_unmarshal_vec(char *marshalled, size_t len)
{
    char **ret, *bp, *ent;
    size_t count, slen;
    int k, j, h;

    if (marshalled == NULL) {
        return (NULL);
    }
    count = 0;
    for (k = 0; k < len; k++) {
       if (marshalled[k] == '\0') {
            count++;
        }
    }
    count--;
    ret = calloc(count + 1, sizeof(char *));
    if (ret == NULL) {
        return (NULL);
    }
    bp = marshalled;
    for (j = 0, k = 0; k < count; k++) {
        slen = strlen(bp);
        if (slen == 0) {
            bp += 1;
            continue;
        }
        ent = strdup(bp);
        if (ent == NULL) {
            for (h = 0; h < j; h++) {
                ent = ret[h];
                free(ent);
            }
            free(ret);
            return (NULL);
        }
        ret[j++] = ent;
        bp += slen;
        bp++;
    }
    ret[j] = NULL;
    return (ret);
}

int privsep_may_read(int fd, void *buf, size_t n)
{
    ssize_t res, pos;
    char *s;

    s = buf;
    pos = 0;
    while (n > pos) {
        res = read(fd, s + pos, n - pos);
        switch (res) {
        case -1:
            if (errno == EINTR || errno == EAGAIN)
                continue;
        case 0:
            return (1);
        default:
            pos += res;
        }
    }
    return (0);
}

void privsep_must_read(int fd, void *buf, size_t n)
{
    extern int privsep_flags;
    ssize_t res, pos;
    char *s;

    pos = 0;
    s = buf;
    while (n > pos) {
        res = read(fd, s + pos, n - pos);
        switch (res) {
        case -1:
            if (errno == EINTR || errno == EAGAIN)
                continue;
            err(1, "read failed");
            /* FALLTHROUGH */
        case 0:
            if ((privsep_flags & PRIVSEP_PRIVILEGED) != 0) {
                _exit(0);
            } else {
                exit(0);
            }
        default:
            pos += res;
        }
    }
}

void privsep_must_readv(int fd, const struct iovec *iov, int iovcnt)
{
    extern int privsep_flags;
    ssize_t cc;

    while (1) {
        cc = readv(fd, iov, iovcnt);
        if (cc == -1 && errno == EINTR) {
            continue;
        }
        if (cc == -1) {
            warn("readv failed");
            if ((privsep_flags & PRIVSEP_PRIVILEGED) != 0) {
                _exit(1);
            } else {
                exit(1);
            }
        }
        break;
    }
}

void privsep_must_writev(int fd, const struct iovec *iov, int iovcnt)
{
    extern int privsep_flags;
    ssize_t cc;

    while (1) {
        cc = writev(fd, iov, iovcnt);
        if (cc == -1 && errno == EINTR) {
            continue;
        }
        if (cc == -1) {
            warn("writev failed");
            if ((privsep_flags & PRIVSEP_PRIVILEGED) != 0) {
                _exit(1);
            } else {
                exit(1);
            }
        }
        break;
    }
}

void privsep_must_write(int fd, void *buf, size_t n)
{
    extern int privsep_flags;
    ssize_t res, pos;
    char *s;

    pos = 0;
    s = buf;
    while (n > pos) {
        res = write(fd, s + pos, n - pos);
        switch (res) {
        case -1:
            if (errno == EINTR || errno == EAGAIN)
                continue;
            err(1, "write failed");
        case 0:
            if ((privsep_flags & PRIVSEP_PRIVILEGED) != 0) {
                _exit(0);
            } else {
                exit(0);
            }
        default:
            pos += res;
        }
    }
}

void privsep_send_fd(int sock, int fd)
{
    struct msghdr msg;
    union {
        struct cmsghdr hdr;
        char buf[CMSG_SPACE(sizeof(int))];
    } cmsgbuf;
    struct cmsghdr *cmsg;
    struct iovec vec;
    int *fdp, result;
    ssize_t n;

    result = 0;
    memset(&msg, 0, sizeof(msg));
    if (fd < 0) {
        return;
    }
    msg.msg_control = (caddr_t)&cmsgbuf.buf;
    msg.msg_controllen = sizeof(cmsgbuf.buf);
    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    fdp = (int *)CMSG_DATA(cmsg);
    *fdp = fd;
    vec.iov_base = &result;
    vec.iov_len = sizeof(int);
    msg.msg_iov = &vec;
    msg.msg_iovlen = 1;
    if ((n = sendmsg(sock, &msg, 0)) == -1)  {
        fprintf(stderr, "privsep_send_fd: %s\n", strerror(errno));
        abort();
    }
    if (n != sizeof(int)) {
        fprintf(stderr, "privsep_send_fd: %s\n", strerror(errno));
        abort();
    }
}

int privsep_receive_fd(int sock)
{
    struct msghdr msg;
    union {
        struct cmsghdr hdr;
        char buf[CMSG_SPACE(sizeof(int))];
    } cmsgbuf;
    struct cmsghdr *cmsg;
    struct iovec vec;
    ssize_t n;
    int result;
    int fd, *fdp;

    memset(&msg, 0, sizeof(msg));
    vec.iov_base = &result;
    vec.iov_len = sizeof(int);
    msg.msg_iov = &vec;
    msg.msg_iovlen = 1;
    msg.msg_control = &cmsgbuf.buf;
    msg.msg_controllen = sizeof(cmsgbuf.buf);
    if ((n = recvmsg(sock, &msg, 0)) == -1) {
        fprintf(stderr, "%s: %s\n", __func__, strerror(errno));
        abort();
    }
    if (n != sizeof(int)) {
        fprintf(stderr, "%s: %s\n", __func__, strerror(errno));
        abort();
    }
    if (result == 0) {
        cmsg = CMSG_FIRSTHDR(&msg);
        if (cmsg == NULL) {
            abort();
        }
        if (cmsg->cmsg_type != SCM_RIGHTS) {
            (void) fprintf(stderr, "%s: expected type %d got %d", __func__,
                SCM_RIGHTS, cmsg->cmsg_type);
            abort();
        }
        fdp = (int *)CMSG_DATA(cmsg);
        fd = *fdp;
        assert(fd != -1);
        return (fd);
    } else {
        errno = result;
        return (-1);
    }
}
