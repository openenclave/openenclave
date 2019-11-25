// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

/*
**==============================================================================
**
** windows/syscall.c:
**
**     This file implements SYSCALL OCALLs for Windows. Most of these are stubs
**     which are still under development.
**
**==============================================================================
*/
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <direct.h>
#include <io.h>
#include <stdint.h>
#include <sys/stat.h>

// clang-format off

#include <winsock2.h>
#include <windows.h>
#include <Ws2def.h>
#include <VersionHelpers.h>
// clang-format on

#include <openenclave/corelibc/errno.h>
#include <openenclave/internal/syscall/fcntl.h>
#include <openenclave/internal/syscall/dirent.h>
#include <openenclave/internal/syscall/unistd.h>
#include "../hostthread.h"
#include "../../common/oe_host_socket.h"
#include "syscall_u.h"

/*
**==============================================================================
**
** WINDOWS ERROR CONVERSION
**
**==============================================================================
*/

struct tab_entry
{
    int key;
    int val;
};

static struct tab_entry winsock2errno[] = {
    {WSAEINTR, OE_EINTR},
    {WSAEBADF, OE_EBADF},
    {WSAEACCES, OE_EACCES},
    {WSAEFAULT, OE_EFAULT},
    {WSAEINVAL, OE_EINVAL},
    {WSAEMFILE, OE_EMFILE},
    {WSAEWOULDBLOCK, OE_EWOULDBLOCK},
    {WSAEINPROGRESS, OE_EINPROGRESS},
    {WSAEALREADY, OE_EALREADY},
    {WSAENOTSOCK, OE_ENOTSOCK},
    {WSAEDESTADDRREQ, OE_EDESTADDRREQ},
    {WSAEMSGSIZE, OE_EMSGSIZE},
    {WSAEPROTOTYPE, OE_EPROTOTYPE},
    {WSAENOPROTOOPT, OE_ENOPROTOOPT},
    {WSAEPROTONOSUPPORT, OE_EPROTONOSUPPORT},
    {WSAESOCKTNOSUPPORT, OE_ESOCKTNOSUPPORT},
    {WSAEOPNOTSUPP, OE_EOPNOTSUPP},
    {WSAEPFNOSUPPORT, OE_EPFNOSUPPORT},
    {WSAEAFNOSUPPORT, OE_EAFNOSUPPORT},
    {WSAEADDRINUSE, OE_EADDRINUSE},
    {WSAEADDRNOTAVAIL, OE_EADDRNOTAVAIL},
    {WSAENETDOWN, OE_ENETDOWN},
    {WSAENETUNREACH, OE_ENETUNREACH},
    {WSAENETRESET, OE_ENETRESET},
    {WSAECONNABORTED, OE_ECONNABORTED},
    {WSAECONNRESET, OE_ECONNRESET},
    {WSAENOBUFS, OE_ENOBUFS},
    {WSAEISCONN, OE_EISCONN},
    {WSAENOTCONN, OE_ENOTCONN},
    {WSAESHUTDOWN, OE_ESHUTDOWN},
    {WSAETOOMANYREFS, OE_ETOOMANYREFS},
    {WSAETIMEDOUT, OE_ETIMEDOUT},
    {WSAECONNREFUSED, OE_ECONNREFUSED},
    {WSAELOOP, OE_ELOOP},
    {WSAENAMETOOLONG, OE_ENAMETOOLONG},
    {WSAEHOSTDOWN, OE_EHOSTDOWN},
    {WSAEHOSTUNREACH, OE_EHOSTUNREACH},
    {WSAENOTEMPTY, OE_ENOTEMPTY},
    {WSAEUSERS, OE_EUSERS},
    {WSAEDQUOT, OE_EDQUOT},
    {WSAESTALE, OE_ESTALE},
    {WSAEREMOTE, OE_EREMOTE},
    {WSAEDISCON, OE_ESHUTDOWN},
    {WSAEPROCLIM, OE_EPROCLIM},
    {WSASYSNOTREADY, OE_EBUSY},
    {WSAVERNOTSUPPORTED, OE_ENOTSUP},
    {WSANOTINITIALISED, OE_ENXIO},
    {0, 0}};

/**
 * Musl libc has redefined pretty much every define in socket.h so that
 * constants passed as parameters are different if the enclave uses musl
 * and the host uses a socket implementation that uses the original BSD
 * defines (winsock, glibc, BSD libc). The following tables are 1-to-1 mappings
 * from musl defines to bsd defines
 */

// Only SOL_SOCKET is different. All other socket level
// defines are the same.
static struct tab_entry musl2bsd_socket_level[] = {{1, SOL_SOCKET}, {0, 0}};

static struct tab_entry musl2bsd_socket_option[] = {{1, SO_DEBUG},
                                                    {2, SO_REUSEADDR},
                                                    {3, SO_TYPE},
                                                    {4, SO_ERROR},
                                                    {5, SO_DONTROUTE},
                                                    {6, SO_BROADCAST},
                                                    {7, SO_SNDBUF},
                                                    {8, SO_RCVBUF},
                                                    {9, SO_KEEPALIVE},
                                                    {10, SO_OOBINLINE},
                                                    {13, SO_LINGER},
                                                    {18, SO_RCVLOWAT},
                                                    {19, SO_SNDLOWAT}};

static struct tab_entry wsa2eai[] = {{WSATRY_AGAIN, OE_EAI_AGAIN},
                                     {WSAEINVAL, OE_EAI_BADFLAGS},
                                     {WSAEAFNOSUPPORT, OE_EAI_FAMILY},
                                     {WSA_NOT_ENOUGH_MEMORY, OE_EAI_MEMORY},
                                     {WSAHOST_NOT_FOUND, OE_EAI_NONAME},
                                     {WSATYPE_NOT_FOUND, OE_EAI_SERVICE},
                                     {WSAESOCKTNOSUPPORT, OE_EAI_SOCKTYPE},
                                     {0, 0}};

static int _do_lookup(int key, int fallback, struct tab_entry* table)
{
    struct tab_entry* pent = table;
    do
    {
        if (pent->key == key)
        {
            return pent->val;
        }

        pent++;
    } while (pent->val != 0);

    return fallback;
}

static int _winsockerr_to_errno(DWORD winsockerr)
{
    return _do_lookup(winsockerr, OE_EINVAL, winsock2errno);
}

static int _wsaerr_to_eai(DWORD winsockerr)
{
    return _do_lookup(winsockerr, OE_EINVAL, wsa2eai);
}

static int _musl_to_bsd(int musl_define, struct tab_entry* table)
{
    return _do_lookup(musl_define, OE_EINVAL, table);
}

/*
**==============================================================================
**
** PANIC -- remove this when no longer needed.
**
**==============================================================================
*/

__declspec(noreturn) static void _panic(
    const char* file,
    unsigned int line,
    const char* function)
{
    fprintf(stderr, "%s(%u): %s(): panic\n", file, line, function);
    abort();
}

#define PANIC _panic(__FILE__, __LINE__, __FUNCTION__)

/*
**==============================================================================
**
** File and directory I/O:
**
**==============================================================================
*/

/* Mask to extract open() access mode flags: O_RDONLY, O_WRONLY, O_RDWR. */
#define OPEN_ACCESS_MODE_MASK 0x00000003

oe_host_fd_t oe_syscall_open_ocall(
    const char* pathname,
    int flags,
    oe_mode_t mode)
{
    oe_host_fd_t ret = -1;

    if (strcmp(pathname, "/dev/stdin") == 0)
    {
        if ((flags & OPEN_ACCESS_MODE_MASK) != OE_O_RDONLY)
        {
            _set_errno(OE_EINVAL);
            goto done;
        }

        ret = _dup(OE_STDIN_FILENO);
        goto done;
    }
    else if (strcmp(pathname, "/dev/stdout") == 0)
    {
        if ((flags & OPEN_ACCESS_MODE_MASK) != OE_O_WRONLY)
        {
            _set_errno(OE_EINVAL);
            goto done;
        }

        ret = _dup(OE_STDOUT_FILENO);
        goto done;
    }
    else if (strcmp(pathname, "/dev/stderr") == 0)
    {
        if ((flags & OPEN_ACCESS_MODE_MASK) != OE_O_WRONLY)
        {
            _set_errno(OE_EINVAL);
            goto done;
        }

        ret = _dup(OE_STDERR_FILENO);
        goto done;
    }
    else
    {
        /* Opening of files not supported on Windows yet. */
        PANIC;
    }

done:

    return ret;
}

ssize_t oe_syscall_read_ocall(oe_host_fd_t fd, void* buf, size_t count)
{
    return _read(fd, buf, count);
}

ssize_t oe_syscall_write_ocall(oe_host_fd_t fd, const void* buf, size_t count)
{
    return _write(fd, buf, count);
}

ssize_t oe_syscall_readv_ocall(
    oe_host_fd_t fd,
    void* iov_buf,
    int iovcnt,
    size_t iov_buf_size)
{
    struct oe_iovec* iov = (struct oe_iovec*)iov_buf;
    ssize_t ret = -1;
    ssize_t size_read;

    errno = 0;

    if ((!iov && iovcnt) || iovcnt < 0 || iovcnt > OE_IOV_MAX)
    {
        errno = EINVAL;
        goto done;
    }

    /* Handle zero data case. */
    if (!iov || iovcnt == 0)
    {
        ret = 0;
        goto done;
    }

    {
        void* buf;
        size_t count;

        buf = &iov[iovcnt];
        count = iov_buf_size - ((size_t)iovcnt * sizeof(struct oe_iovec));

        size_read = oe_syscall_read_ocall(fd, buf, count);
    }

    ret = size_read;

done:
    return ret;
}

ssize_t oe_syscall_writev_ocall(
    oe_host_fd_t fd,
    const void* iov_buf,
    int iovcnt,
    size_t iov_buf_size)
{
    ssize_t ret = -1;
    ssize_t size_written;
    struct oe_iovec* iov = (struct oe_iovec*)iov_buf;

    errno = 0;

    if ((!iov && iovcnt) || iovcnt < 0 || iovcnt > OE_IOV_MAX)
    {
        errno = EINVAL;
        goto done;
    }

    /* Handle zero data case. */
    if (!iov || iovcnt == 0)
    {
        ret = 0;
        goto done;
    }

    {
        const void* buf;
        size_t count;

        buf = &iov[iovcnt];
        count = iov_buf_size - ((size_t)iovcnt * sizeof(struct oe_iovec));

        size_written = oe_syscall_write_ocall(fd, buf, count);
    }

    ret = size_written;

done:
    return ret;
}

oe_off_t oe_syscall_lseek_ocall(oe_host_fd_t fd, oe_off_t offset, int whence)
{
    PANIC;
}

int oe_syscall_close_ocall(oe_host_fd_t fd)
{
    return _close(fd);
}

static oe_host_fd_t _dup_socket(oe_host_fd_t);

oe_host_fd_t oe_syscall_dup_ocall(oe_host_fd_t oldfd)
{
    oe_host_fd_t ret = -1;

    // Only support duping std file descriptors and sockets for now.
    switch (oldfd)
    {
        case 0:
            ret = _dup(OE_STDIN_FILENO);
            break;

        case 1:
            ret = _dup(OE_STDOUT_FILENO);
            break;

        case 2:
            ret = _dup(OE_STDERR_FILENO);
            break;

        default:
            // Try dup-ing it as a socket.
            ret = _dup_socket(oldfd);
            break;
    }

    if (ret == -1)
        _set_errno(OE_EINVAL);
    else
        _set_errno(0);

    return ret;
}

uint64_t oe_syscall_opendir_ocall(const char* pathname)
{
    PANIC;
}

int oe_syscall_readdir_ocall(uint64_t dirp, struct oe_dirent* entry)
{
    PANIC;
}

void oe_syscall_rewinddir_ocall(uint64_t dirp)
{
    PANIC;
}

int oe_syscall_closedir_ocall(uint64_t dirp)
{
    PANIC;
}

int oe_syscall_stat_ocall(const char* pathname, struct oe_stat* buf)
{
    PANIC;
}

int oe_syscall_access_ocall(const char* pathname, int mode)
{
    PANIC;
}

int oe_syscall_link_ocall(const char* oldpath, const char* newpath)
{
    PANIC;
}

int oe_syscall_unlink_ocall(const char* pathname)
{
    PANIC;
}

int oe_syscall_rename_ocall(const char* oldpath, const char* newpath)
{
    PANIC;
}

int oe_syscall_truncate_ocall(const char* pathname, oe_off_t length)
{
    PANIC;
}

int oe_syscall_mkdir_ocall(const char* pathname, oe_mode_t mode)
{
    PANIC;
}

int oe_syscall_rmdir_ocall(const char* pathname)
{
    PANIC;
}

/*
**==============================================================================
**
** Socket I/O:
**
**==============================================================================
*/

#define OE_SOCKET_FD_MAGIC 0x29b4a345c7564b57
typedef struct win_socket_fd
{
    uint64_t magic;
    SOCKET socket;
} oe_socket_fd_t;

static oe_socket_fd_t _invalid_socket = {OE_SOCKET_FD_MAGIC, INVALID_SOCKET};

oe_host_fd_t _make_socket_fd(SOCKET sock)
{
    oe_host_fd_t fd = (oe_host_fd_t)&_invalid_socket;
    if (sock != INVALID_SOCKET)
    {
        oe_socket_fd_t* socket_fd =
            (oe_socket_fd_t*)malloc(sizeof(oe_socket_fd_t));
        socket_fd->magic = OE_SOCKET_FD_MAGIC;
        socket_fd->socket = sock;
        fd = (oe_host_fd_t)socket_fd;
    }
    return fd;
}

SOCKET _get_socket(oe_host_fd_t fd)
{
    oe_socket_fd_t* socket_fd = (oe_socket_fd_t*)fd;
    if (socket_fd && socket_fd->magic == OE_SOCKET_FD_MAGIC)
        return socket_fd->socket;
    return INVALID_SOCKET;
}

static oe_host_fd_t _dup_socket(oe_host_fd_t oldfd)
{
    oe_socket_fd_t* old_socket_fd = (oe_socket_fd_t*)oldfd;
    if (old_socket_fd && old_socket_fd->magic == OE_SOCKET_FD_MAGIC)
    {
        oe_socket_fd_t* new_socket_fd =
            (oe_socket_fd_t*)malloc(sizeof(oe_socket_fd_t));
        if (new_socket_fd)
        {
            *new_socket_fd = *old_socket_fd;
            return (oe_host_fd_t)(uint64_t)new_socket_fd;
        }
        else
        {
            _set_errno(OE_ENOMEM);
        }
    }
    return -1;
}

static int _wsa_startup()
{
    static bool wsa_init_done = FALSE;
    WSADATA wsaData;
    int ret = 0;

    if (!wsa_init_done)
    {
        ret = WSAStartup(2, &wsaData);
        if (ret != 0)
            goto done;

        wsa_init_done = TRUE;
    }

done:
    return ret;
}

oe_host_fd_t oe_syscall_socket_ocall(int domain, int type, int protocol)
{
    SOCKET sock = INVALID_SOCKET;

    if (_wsa_startup() != 0)
    {
        _set_errno(OE_EINVAL);
        goto done;
    }

    sock = socket(domain, type, protocol);
    if (sock == INVALID_SOCKET)
    {
        _set_errno(_winsockerr_to_errno(WSAGetLastError()));
    }

done:
    return _make_socket_fd(sock);
}

int oe_syscall_socketpair_ocall(
    int domain,
    int type,
    int protocol,
    oe_host_fd_t sv_out[2])
{
    PANIC;
}

int oe_syscall_connect_ocall(
    oe_host_fd_t sockfd,
    const struct oe_sockaddr* addr,
    oe_socklen_t addrlen)
{
    int ret = connect(
        _get_socket(sockfd), (const struct sockaddr*)addr, (int)addrlen);
    if (ret != 0)
    {
        _set_errno(_winsockerr_to_errno(WSAGetLastError()));
    }

    return ret;
}

oe_host_fd_t oe_syscall_accept_ocall(
    oe_host_fd_t sockfd,
    struct oe_sockaddr* addr,
    oe_socklen_t addrlen_in,
    oe_socklen_t* addrlen_out)
{
    int addrlen = (int)addrlen_in;
    SOCKET conn_socket = accept(
        _get_socket(sockfd),
        (struct sockaddr*)addr,
        addrlen_out ? &addrlen : NULL);
    if (conn_socket == INVALID_SOCKET)
    {
        _set_errno(_winsockerr_to_errno(WSAGetLastError()));
        goto done;
    }

    if (addrlen_out)
        *addrlen_out = addrlen;

done:
    return _make_socket_fd(conn_socket);
}

int oe_syscall_bind_ocall(
    oe_host_fd_t sockfd,
    const struct oe_sockaddr* addr,
    oe_socklen_t addrlen)
{
    int ret = bind(_get_socket(sockfd), (const struct sockaddr*)addr, addrlen);
    if (ret != 0)
    {
        _set_errno(_winsockerr_to_errno(WSAGetLastError()));
    }

    return ret;
}

int oe_syscall_listen_ocall(oe_host_fd_t sockfd, int backlog)
{
    int ret = listen(_get_socket(sockfd), backlog);
    if (ret != 0)
    {
        _set_errno(_winsockerr_to_errno(WSAGetLastError()));
    }

    return ret;
}

ssize_t oe_syscall_recvmsg_ocall(
    oe_host_fd_t sockfd,
    void* msg_name,
    oe_socklen_t msg_namelen,
    oe_socklen_t* msg_namelen_out,
    void* msg_iov_buf,
    size_t msg_iovlen,
    size_t msg_iov_buf_size,
    void* msg_control,
    size_t msg_controllen,
    size_t* msg_controllen_out,
    int flags)
{
    PANIC;
}

ssize_t oe_syscall_sendmsg_ocall(
    oe_host_fd_t sockfd,
    const void* msg_name,
    oe_socklen_t msg_namelen,
    void* msg_iov_buf,
    size_t msg_iovlen,
    size_t msg_iov_buf_size,
    const void* msg_control,
    size_t msg_controllen,
    int flags)
{
    PANIC;
}

ssize_t oe_syscall_recv_ocall(
    oe_host_fd_t sockfd,
    void* buf,
    size_t len,
    int flags)
{
    ssize_t ret;
    _set_errno(0);

    ret = recv(_get_socket(sockfd), (char*)buf, (int)len, flags);
    if (ret == SOCKET_ERROR)
    {
        _set_errno(_winsockerr_to_errno(WSAGetLastError()));
    }

    return ret;
}

ssize_t oe_syscall_recvfrom_ocall(
    oe_host_fd_t sockfd,
    void* buf,
    size_t len,
    int flags,
    struct oe_sockaddr* src_addr,
    oe_socklen_t addrlen_in,
    oe_socklen_t* addrlen_out)
{
    ssize_t ret;
    _set_errno(0);

    ret = recvfrom(
        _get_socket(sockfd),
        (char*)buf,
        (int)len,
        flags,
        (struct sockaddr*)src_addr,
        addrlen_in);
    if (ret == SOCKET_ERROR)
    {
        _set_errno(_winsockerr_to_errno(WSAGetLastError()));
    }
    else
    {
        if (addrlen_out)
            *addrlen_out = addrlen_in;
    }

    return ret;
}

ssize_t oe_syscall_send_ocall(
    oe_host_fd_t sockfd,
    const void* buf,
    size_t len,
    int flags)
{
    ssize_t ret;
    _set_errno(0);

    ret = send(_get_socket(sockfd), buf, len, flags);
    if (ret == SOCKET_ERROR)
    {
        _set_errno(_winsockerr_to_errno(WSAGetLastError()));
    }

    return ret;
}

ssize_t oe_syscall_sendto_ocall(
    oe_host_fd_t sockfd,
    const void* buf,
    size_t len,
    int flags,
    const struct oe_sockaddr* src_addr,
    oe_socklen_t addrlen)
{
    ssize_t ret;
    _set_errno(0);

    ret = sendto(
        _get_socket(sockfd),
        buf,
        len,
        flags,
        (struct sockaddr*)src_addr,
        addrlen);
    if (ret == SOCKET_ERROR)
    {
        _set_errno(_winsockerr_to_errno(WSAGetLastError()));
    }

    return ret;
}

ssize_t oe_syscall_recvv_ocall(
    oe_host_fd_t fd,
    void* iov_buf,
    int iovcnt,
    size_t iov_buf_size)
{
    PANIC;
}

ssize_t oe_syscall_sendv_ocall(
    oe_host_fd_t fd,
    const void* iov_buf,
    int iovcnt,
    size_t iov_buf_size)
{
    PANIC;
}

int oe_syscall_shutdown_ocall(oe_host_fd_t sockfd, int how)
{
    int ret = shutdown(_get_socket(sockfd), how);
    if (ret != 0)
    {
        _set_errno(_winsockerr_to_errno(WSAGetLastError()));
    }

    return ret;
}

int oe_syscall_close_socket_ocall(oe_host_fd_t sockfd)
{
    SOCKET sock = _get_socket(sockfd);
    int r = -1;
    if (sock != INVALID_SOCKET)
    {
        r = closesocket(sock);
        if (r != 0)
        {
            _set_errno(_winsockerr_to_errno(WSAGetLastError()));
        }

        free((oe_socket_fd_t*)sockfd);
    }
    return r;
}

#define F_GETFL 3

int oe_syscall_fcntl_ocall(
    oe_host_fd_t fd,
    int cmd,
    uint64_t arg,
    uint64_t argsize,
    void* argout)
{
    SOCKET sock;

    if ((sock = _get_socket(fd)) != INVALID_SOCKET)
    {
        switch (cmd)
        {
            case F_GETFL:
                // TODO: There is no way to get file access modes on winsock
                // sockets. Currently this only exists to because mbedtls uses
                // this syscall to check if the socket is blocking. If we want
                // this syscall to actually work properly for other cases, this
                // should be revisited.
                return 0;
            default:
                PANIC;
        }
    }
    else
    {
        // File operations are not supported
        PANIC;
    }
}

#define TIOCGWINSZ 0x5413
#define TIOCSWINSZ 0x5414

int oe_syscall_ioctl_ocall(
    oe_host_fd_t fd,
    uint64_t request,
    uint64_t arg,
    uint64_t argsize,
    void* argout)
{
    errno = 0;

    // We don't support any ioctls right now as we will have to translate the
    // codes from the enclave to be the equivelent for windows. But... no such
    // codes are currently being used So we panic to highlight the problem line
    // of code. In this way, we can see what ioctls are needed

    switch (request)
    {
        case TIOCGWINSZ:
        case TIOCSWINSZ:
            _set_errno(OE_ENOTTY);
            break;
        default:
            _set_errno(OE_EINVAL);
            break;
    }

    return -1;
}

int oe_syscall_setsockopt_ocall(
    oe_host_fd_t sockfd,
    int level,
    int optname,
    const void* optval,
    oe_socklen_t optlen)
{
    level = _musl_to_bsd(level, musl2bsd_socket_level);
    optname = _musl_to_bsd(optname, musl2bsd_socket_option);

    int ret = setsockopt(_get_socket(sockfd), level, optname, optval, optlen);
    if (ret != 0)
    {
        int err = _winsockerr_to_errno(WSAGetLastError());
        _set_errno(err);
    }

    return ret;
}

int oe_syscall_getsockopt_ocall(
    oe_host_fd_t sockfd,
    int level,
    int optname,
    void* optval,
    oe_socklen_t optlen_in,
    oe_socklen_t* optlen_out)
{
    level = _musl_to_bsd(level, musl2bsd_socket_level);
    optname = _musl_to_bsd(optname, musl2bsd_socket_option);

    int ret =
        getsockopt(_get_socket(sockfd), level, optname, optval, &optlen_in);
    if (ret != 0)
    {
        int err = _winsockerr_to_errno(WSAGetLastError());
        _set_errno(err);
    }
    else
    {
        if (optlen_out)
            *optlen_out = optlen_in;
    }

    return ret;
}

int oe_syscall_getsockname_ocall(
    oe_host_fd_t sockfd,
    struct oe_sockaddr* addr,
    oe_socklen_t addrlen_in,
    oe_socklen_t* addrlen_out)
{
    PANIC;
}

int oe_syscall_getpeername_ocall(
    oe_host_fd_t sockfd,
    struct oe_sockaddr* addr,
    oe_socklen_t addrlen_in,
    oe_socklen_t* addrlen_out)
{
    PANIC;
}

int oe_syscall_shutdown_sockets_device_ocall(oe_host_fd_t sockfd)
{
    PANIC;
}

/*
**==============================================================================
**
** Signals:
**
**==============================================================================
*/

int oe_syscall_kill_ocall(int pid, int signum)
{
    PANIC;
}

/*
**==============================================================================
**
** Resolver:
**
**==============================================================================
*/

int oe_syscall_getaddrinfo_open_ocall(
    const char* node,
    const char* service,
    const struct oe_addrinfo* hints,
    uint64_t* handle_out)
{
    int ret = OE_EAI_FAIL;
    getaddrinfo_handle_t* handle = NULL;

    if (_wsa_startup() != 0)
    {
        _set_errno(OE_EINVAL);
        goto done;
    }

    _set_errno(0);

    if (handle_out)
    {
        *handle_out = 0;
    }
    else
    {
        ret = OE_EAI_SYSTEM;
        _set_errno(OE_EINVAL);
        goto done;
    }

    if (!(handle = calloc(1, sizeof(getaddrinfo_handle_t))))
    {
        ret = OE_EAI_MEMORY;
        _set_errno(OE_ENOMEM);
        goto done;
    }

    ret =
        getaddrinfo(node, service, (const struct addrinfo*)hints, &handle->res);
    if (ret == 0)
    {
        handle->magic = GETADDRINFO_HANDLE_MAGIC;
        handle->next = handle->res;
        *handle_out = (uint64_t)handle;
        handle = NULL;
    }
    else
    {
        ret = _wsaerr_to_eai(ret);
    }

done:

    if (handle)
        free(handle);

    return ret;
}

int oe_syscall_getaddrinfo_read_ocall(
    uint64_t handle_,
    int* ai_flags,
    int* ai_family,
    int* ai_socktype,
    int* ai_protocol,
    oe_socklen_t ai_addrlen_in,
    oe_socklen_t* ai_addrlen,
    struct oe_sockaddr* ai_addr,
    size_t ai_canonnamelen_in,
    size_t* ai_canonnamelen,
    char* ai_canonname)
{
    int err_no = 0;
    int ret = _getaddrinfo_read(
        handle_,
        ai_flags,
        ai_family,
        ai_socktype,
        ai_protocol,
        ai_addrlen_in,
        ai_addrlen,
        ai_addr,
        ai_canonnamelen_in,
        ai_canonnamelen,
        ai_canonname,
        &err_no);
    _set_errno(err_no);

    return ret;
}

int oe_syscall_getaddrinfo_close_ocall(uint64_t handle_)
{
    int ret = -1;
    getaddrinfo_handle_t* handle = _cast_getaddrinfo_handle((void*)handle_);

    _set_errno(0);

    if (!handle)
    {
        _set_errno(OE_EINVAL);
        goto done;
    }

    freeaddrinfo(handle->res);
    free(handle);

    ret = 0;

done:
    return ret;
}

int oe_syscall_getnameinfo_ocall(
    const struct oe_sockaddr* sa,
    oe_socklen_t salen,
    char* host,
    oe_socklen_t hostlen,
    char* serv,
    oe_socklen_t servlen,
    int flags)
{
    PANIC;
}

/*
**==============================================================================
**
** Polling:
**
**==============================================================================
*/

oe_host_fd_t oe_syscall_epoll_create1_ocall(int flags)
{
    PANIC;
}

int oe_syscall_epoll_wait_ocall(
    int64_t epfd,
    struct oe_epoll_event* events,
    unsigned int maxevents,
    int timeout)
{
    PANIC;
}

int oe_syscall_epoll_wake_ocall(void)
{
    PANIC;
}

int oe_syscall_epoll_ctl_ocall(
    int64_t epfd,
    int op,
    int64_t fd,
    struct oe_epoll_event* event)
{
    PANIC;
}

int oe_syscall_epoll_close_ocall(oe_host_fd_t epfd)
{
    PANIC;
}

/*
**==============================================================================
**
** poll()
**
**==============================================================================
*/

int oe_syscall_poll_ocall(
    struct oe_host_pollfd* host_fds,
    oe_nfds_t nfds,
    int timeout)
{
    PANIC;
}

/*
**==============================================================================
**
** uid, gid, pid, and groups:
**
**==============================================================================
*/

int oe_syscall_getpid_ocall(void)
{
    PANIC;
}

int oe_syscall_getppid_ocall(void)
{
    PANIC;
}

int oe_syscall_getpgrp_ocall(void)
{
    PANIC;
}

unsigned int oe_syscall_getuid_ocall(void)
{
    PANIC;
}

unsigned int oe_syscall_geteuid_ocall(void)
{
    PANIC;
}

unsigned int oe_syscall_getgid_ocall(void)
{
    PANIC;
}

unsigned int oe_syscall_getegid_ocall(void)
{
    PANIC;
}

int oe_syscall_getpgid_ocall(int pid)
{
    PANIC;
}

int oe_syscall_getgroups_ocall(size_t size, unsigned int* list)
{
    PANIC;
}

/*
**==============================================================================
**
** uname():
**
**==============================================================================
*/

int oe_syscall_uname_ocall(struct oe_utsname* buf)
{
    // Based on
    // https://docs.microsoft.com/en-us/windows/win32/sysinfo/getting-the-system-version
    // OE SDK is supported only on WindowsServer and Win10
    if (IsWindowsServer())
    {
        sprintf(buf->nodename, "(unknown)");
        sprintf(buf->domainname, "(none)");
        sprintf(buf->sysname, "WindowsServer");
        sprintf(buf->version, "2016OrAbove");
        return 0;
    }
    else if (IsWindows10OrGreater())
    {
        sprintf(buf->nodename, "(unknown)");
        sprintf(buf->domainname, "(none)");
        sprintf(buf->sysname, "Windows10OrGreater");
        sprintf(buf->version, "10OrAbove");
        return 0;
    }

    return -1;
}
