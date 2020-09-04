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
#ifndef PRIVSEP_DOT_H_
#define PRIVSEP_DOT_H_
#include <sys/types.h>
#include <pwd.h>

struct privsep_thread_specific {
    int                 sock;
};
typedef struct privsep_thread_specific privsep_thread_specific_t;

struct privsep_worker {
    int                 sock;
    pthread_t           thr;
};
typedef struct privsep_worker privsep_worker_t;

struct privsep_waitpid {
    pid_t               pid;
    int                 options;
};
typedef struct privsep_waitpid privsep_waitpid_t;


struct privsep_sendmsg {
    size_t              msg_namelen;
    size_t              msg_iovlen;
    size_t              msg_controllen;
    int                 flags;
};
typedef struct privsep_sendmsg privsep_sendmsg_t;

struct privsep_open {
    char                    path[512];
    int                     flags;
    mode_t                  mode;
};
typedef struct privsep_open privsep_open_t;

struct privsep_getaddrinfo {
    char                    hostname[256];
    char                    servname[256];
    struct addrinfo         hints;
};
typedef struct privsep_getaddrinfo privsep_getaddrinfo_t;

struct privsep_getaddrinfo_result {
    int                     ai_flags;
	int                     ai_family;
	int                     ai_socktype;
	int                     ai_protocol;
	socklen_t               ai_addrlen;
	struct sockaddr_storage sas;
	char                    ai_canonname[256];
};
typedef struct privsep_getaddrinfo_result privsep_getaddrinfo_result_t;

struct privsep {
    char *                  user;
};
typedef struct privsep privsep_t;

#define PRIVSEP_STATE_ACTIVE    1
#define PRIVSEP_STATE_OFF       2

/*
 * Define a set of privsep features. These flags will control OS specific
 * aspects of the sandboxing operations.
 */
#define SANDBOX_ALLOWS_SENDMSG  0x0000000000000001
#define PRIVSEP_PRIVILEGED      0x0000000000000002
#define PRIVSEP_NON_PRIVILEGED  0x0000000000000004

enum {
    SANDBOX_POLICY_NONE,
    SANDBOX_POLICY_NEVERBLEED,
    SANDBOX_POLICY_H2OMAIN
};

enum {
    PRIV_NONE,
    PRIV_OPEN,
    PRIV_GETADDRINFO,
    PRIV_SENDMSG,
    PRIV_WAITPID,
    PRIV_GMTIME,
    PRIV_LOCALTIME
};

int         privsep_init(privsep_t *);
char *      privsep_marshal_vec(char *const [], size_t *);
char **     privsep_unmarshal_vec(char *, size_t);
int         privsep_may_read(int, void *, size_t);
void        privsep_must_read(int, void *, size_t);
void        privsep_must_readv(int, const struct iovec *, int);
void        privsep_must_writev(int, const struct iovec *, int);
void        privsep_must_write(int, void *, size_t);
void        privsep_send_fd(int, int);
int         privsep_receive_fd(int);
/*
 * Sandbox interfaces (i.e. functions that will be getting called from
 * within the privsep sandbox
 */
FILE *      privsep_fopen(const char *, const char *);
struct tm * privsep_localtime_r(const time_t *, struct tm *);
struct tm * privsep_gmtime_r(const time_t *, struct tm *);
int         privsep_set_sock(int sock);
pid_t       privsep_waitpid(pid_t, int *, int);
ssize_t     privsep_sendmsg(int, struct msghdr *, int);
void        privsep_bind_sandbox(int policy);
int         privsep_open(const char *, int, ...);
void        privsep_freeaddrinfo(struct addrinfo *);
int         privsep_getaddrinfo(const char *, const char *,
              const struct addrinfo *, struct addrinfo **);

#endif /* PRIVSEP_DOT_H_ */
