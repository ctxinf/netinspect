/*
 * libnetinspect.so - LD_PRELOAD TCP connect redirector for the netinspect
 * project (MIT license).
 *
 * Intercepts connect(2) on TCP sockets and reroutes the connection through
 * a local SOCKS5 proxy, then reports the original destination as a short
 * ASCII record on a Unix datagram socket. Connection-level redirection only:
 * no MITM, no payload inspection, no content capture.
 *
 * Environment:
 *   NETINSPECT_SOCKS_PORT  decimal port of the local SOCKS5 proxy
 *                          (listening on 127.0.0.1)
 *   NETINSPECT_DASH_PORT   decimal port of the local dashboard; connections
 *                          to 127.0.0.1/::1 at either port bypass the proxy
 *                          (loopback protection, avoids recursion)
 *   NETINSPECT_SOCK_PATH   Unix datagram socket path receiving MAP records:
 *                          "MAP <srcport> <pid> <origIP> <origPort> preload"
 *
 * Original code; written from scratch for netinspect.
 */

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

typedef int (*connect_fn_t)(int, const struct sockaddr *, socklen_t);

static connect_fn_t real_connect = NULL;
static pthread_once_t init_once = PTHREAD_ONCE_INIT;

static void init_real_connect(void) {
    /* RTLD_NEXT skips this library itself; dlsym is thread-safe. */
    real_connect = (connect_fn_t)dlsym(RTLD_NEXT, "connect");
}

/* Parse a decimal port from the environment; -1 when missing/invalid. */
static int env_port(const char *name) {
    const char *s = getenv(name);
    char *end = NULL;
    long v;

    if (s == NULL || *s == '\0')
        return -1;
    errno = 0;
    v = strtol(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0' || v <= 0 || v > 65535)
        return -1;
    return (int)v;
}

static ssize_t write_full(int fd, const void *buf, size_t n) {
    const uint8_t *p = (const uint8_t *)buf;
    size_t done = 0;

    while (done < n) {
        ssize_t r = write(fd, p + done, n - done);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (r == 0)
            return -1;
        done += (size_t)r;
    }
    return (ssize_t)done;
}

static ssize_t read_full(int fd, void *buf, size_t n) {
    uint8_t *p = (uint8_t *)buf;
    size_t done = 0;

    while (done < n) {
        ssize_t r = read(fd, p + done, n - done);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (r == 0)
            return -1; /* EOF before the message completed */
        done += (size_t)r;
    }
    return (ssize_t)done;
}

/* Perform the SOCKS5 handshake for the original destination.
 * fd is already connected (blocking) to the proxy. Returns 0 on success,
 * -1 on failure. */
static int socks5_handshake(int fd, const struct sockaddr *addr) {
    static const uint8_t hello[3] = {0x05, 0x01, 0x00}; /* VER=5, 1 method, NO AUTH */
    uint8_t method_resp[2];
    uint8_t req[4 + 16 + 2]; /* VER CMD RSV ATYP + up to 16 addr bytes + 2 port bytes */
    uint8_t conn_resp[10];
    size_t reqlen;

    if (write_full(fd, hello, sizeof(hello)) != (ssize_t)sizeof(hello))
        return -1;
    if (read_full(fd, method_resp, sizeof(method_resp)) != (ssize_t)sizeof(method_resp))
        return -1;
    if (method_resp[0] != 0x05 || method_resp[1] != 0x00)
        return -1;

    req[0] = 0x05; /* VER */
    req[1] = 0x01; /* CMD = CONNECT */
    req[2] = 0x00; /* RSV */
    if (addr->sa_family == AF_INET) {
        const struct sockaddr_in *a4 = (const struct sockaddr_in *)addr;
        req[3] = 0x01; /* ATYP = IPv4 */
        memcpy(req + 4, &a4->sin_addr, 4);
        memcpy(req + 8, &a4->sin_port, 2); /* port already in network order */
        reqlen = 4 + 4 + 2;
    } else {
        const struct sockaddr_in6 *a6 = (const struct sockaddr_in6 *)addr;
        req[3] = 0x04; /* ATYP = IPv6 */
        memcpy(req + 4, &a6->sin6_addr, 16);
        memcpy(req + 20, &a6->sin6_port, 2); /* port already in network order */
        reqlen = 4 + 16 + 2;
    }

    if (write_full(fd, req, reqlen) != (ssize_t)reqlen)
        return -1;
    /* Reply with IPv4 bound address: 05 REP 00 01 00 00 00 00 00 00 */
    if (read_full(fd, conn_resp, sizeof(conn_resp)) != (ssize_t)sizeof(conn_resp))
        return -1;
    if (conn_resp[0] != 0x05 || conn_resp[1] != 0x00)
        return -1;
    return 0;
}

/* Report the successful redirection; best-effort, never fails connect(). */
static void report_map(uint16_t srcport, const char *dst_ip, uint16_t dst_port) {
    const char *sock_path = getenv("NETINSPECT_SOCK_PATH");
    char msg[256];
    int mlen;
    int us;
    struct sockaddr_un un;

    if (sock_path == NULL || *sock_path == '\0')
        return;
    mlen = snprintf(msg, sizeof(msg), "MAP %u %d %s %u preload\n",
                    (unsigned int)srcport, (int)getpid(),
                    dst_ip, (unsigned int)dst_port);
    if (mlen <= 0 || mlen >= (int)sizeof(msg))
        return;

    us = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (us < 0)
        return;
    memset(&un, 0, sizeof(un));
    un.sun_family = AF_UNIX;
    strncpy(un.sun_path, sock_path, sizeof(un.sun_path) - 1);
    /* Unbound datagram socket; destination does not need to be connected. */
    sendto(us, msg, (size_t)mlen, 0, (struct sockaddr *)&un, sizeof(un));
    close(us);
}

int connect(int fd, const struct sockaddr *addr, socklen_t len) {
    int saved_errno = errno;
    int fam;
    int so_type = 0;
    socklen_t so_type_len = sizeof(so_type);
    char dst_ip[INET6_ADDRSTRLEN];
    uint16_t dst_port = 0;
    int is_loopback = 0;
    int socks_port, dash_port;
    int flags, was_nonblock;
    int rc;
    struct sockaddr_storage local;
    socklen_t loclen = sizeof(local);
    uint16_t srcport = 0;

    pthread_once(&init_once, init_real_connect);
    errno = saved_errno; /* keep the caller's errno across init */
    if (real_connect == NULL) {
        errno = ENOSYS;
        return -1;
    }

    if (addr == NULL)
        return real_connect(fd, addr, len);

    fam = addr->sa_family;
    if (fam != AF_INET && fam != AF_INET6)
        return real_connect(fd, addr, len); /* not IP: pass through */

    /* Only TCP sockets are redirected. getsockopt failing (e.g. bad fd)
     * means pass through as well. */
    if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &so_type, &so_type_len) != 0 ||
        so_type != SOCK_STREAM)
        return real_connect(fd, addr, len);

    /* Extract numeric destination; IP literals only (sockaddr_in/_in6
     * always carry numeric addresses). */
    if (fam == AF_INET) {
        const struct sockaddr_in *a4 = (const struct sockaddr_in *)addr;
        if (len < (socklen_t)sizeof(struct sockaddr_in))
            return real_connect(fd, addr, len);
        if (inet_ntop(AF_INET, &a4->sin_addr, dst_ip, sizeof(dst_ip)) == NULL)
            return real_connect(fd, addr, len);
        dst_port = ntohs(a4->sin_port);
        is_loopback = (ntohl(a4->sin_addr.s_addr) == 0x7F000001u);
    } else {
        const struct sockaddr_in6 *a6 = (const struct sockaddr_in6 *)addr;
        if (len < (socklen_t)sizeof(struct sockaddr_in6))
            return real_connect(fd, addr, len);
        if (inet_ntop(AF_INET6, &a6->sin6_addr, dst_ip, sizeof(dst_ip)) == NULL)
            return real_connect(fd, addr, len);
        dst_port = ntohs(a6->sin6_port);
        is_loopback = IN6_IS_ADDR_LOOPBACK(&a6->sin6_addr);
        /* ::ffff:127.0.0.1 is the same loopback endpoint as 127.0.0.1. */
        if (!is_loopback && IN6_IS_ADDR_V4MAPPED(&a6->sin6_addr)) {
            uint32_t v4;
            memcpy(&v4, &a6->sin6_addr.s6_addr[12], sizeof(v4));
            is_loopback = (ntohl(v4) == 0x7F000001u);
        }
    }

    socks_port = env_port("NETINSPECT_SOCKS_PORT");
    dash_port = env_port("NETINSPECT_DASH_PORT");

    /* Loopback protection: never proxy the proxy or the dashboard. */
    if (is_loopback && ((int)dst_port == socks_port || (int)dst_port == dash_port))
        return real_connect(fd, addr, len);

    if (socks_port < 0)
        return real_connect(fd, addr, len); /* misconfigured: do no harm */

    /* Non-blocking sockets: do the handshake in blocking mode, then
     * restore the original flags (approximate semantics). */
    flags = fcntl(fd, F_GETFL, 0);
    was_nonblock = (flags >= 0) && ((flags & O_NONBLOCK) != 0);
    if (was_nonblock)
        fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);

    /* The proxy endpoint is 127.0.0.1, but an AF_INET6 socket cannot
     * connect() to a sockaddr_in; use the IPv4-mapped form ::ffff:127.0.0.1
     * (same endpoint, valid family for the socket). */
    if (fam == AF_INET6) {
        struct sockaddr_in6 p6;
        memset(&p6, 0, sizeof(p6));
        p6.sin6_family = AF_INET6;
        p6.sin6_port = htons((uint16_t)socks_port);
        p6.sin6_addr.s6_addr[10] = 0xFF;
        p6.sin6_addr.s6_addr[11] = 0xFF;
        p6.sin6_addr.s6_addr[12] = 127;
        p6.sin6_addr.s6_addr[13] = 0;
        p6.sin6_addr.s6_addr[14] = 0;
        p6.sin6_addr.s6_addr[15] = 1;
        rc = real_connect(fd, (struct sockaddr *)&p6, sizeof(p6));
    } else {
        struct sockaddr_in proxy;
        memset(&proxy, 0, sizeof(proxy));
        proxy.sin_family = AF_INET;
        proxy.sin_port = htons((uint16_t)socks_port);
        proxy.sin_addr.s_addr = htonl(0x7F000001u); /* 127.0.0.1 */
        rc = real_connect(fd, (struct sockaddr *)&proxy, sizeof(proxy));
    }
    if (rc != 0) {
        int e = errno;
        if (was_nonblock)
            fcntl(fd, F_SETFL, flags);
        errno = e; /* surface the proxy-connection failure */
        return -1;
    }

    if (socks5_handshake(fd, addr) != 0) {
        if (was_nonblock)
            fcntl(fd, F_SETFL, flags);
        errno = ECONNREFUSED;
        return -1;
    }

    if (getsockname(fd, (struct sockaddr *)&local, &loclen) == 0) {
        if (local.ss_family == AF_INET)
            srcport = ntohs(((struct sockaddr_in *)&local)->sin_port);
        else if (local.ss_family == AF_INET6)
            srcport = ntohs(((struct sockaddr_in6 *)&local)->sin6_port);
    }
    report_map(srcport, dst_ip, dst_port);

    if (was_nonblock)
        fcntl(fd, F_SETFL, flags);
    errno = saved_errno;
    return 0;
}
