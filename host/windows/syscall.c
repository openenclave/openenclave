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
#include <openenclave/internal/atomic.h>
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

static struct tab_entry winerr2errno[] = {
    {ERROR_ACCESS_DENIED, OE_EACCES},
    {ERROR_ACTIVE_CONNECTIONS, OE_EAGAIN},
    {ERROR_ALREADY_EXISTS, OE_EEXIST},
    {ERROR_BAD_DEVICE, OE_ENODEV},
    {ERROR_BAD_EXE_FORMAT, OE_ENOEXEC},
    {ERROR_BAD_NETPATH, OE_ENOENT},
    {ERROR_BAD_NET_NAME, OE_ENOENT},
    {ERROR_BAD_NET_RESP, OE_ENOSYS},
    {ERROR_BAD_PATHNAME, OE_ENOENT},
    {ERROR_BAD_PIPE, OE_EINVAL},
    {ERROR_BAD_UNIT, OE_ENODEV},
    {ERROR_BAD_USERNAME, OE_EINVAL},
    {ERROR_BEGINNING_OF_MEDIA, OE_EIO},
    {ERROR_BROKEN_PIPE, OE_EPIPE},
    {ERROR_BUSY, OE_EBUSY},
    {ERROR_BUS_RESET, OE_EIO},
    {ERROR_CALL_NOT_IMPLEMENTED, OE_ENOSYS},
    {ERROR_CANCELLED, OE_EINTR},
    {ERROR_CANNOT_MAKE, OE_EPERM},
    {ERROR_CHILD_NOT_COMPLETE, OE_EBUSY},
    {ERROR_COMMITMENT_LIMIT, OE_EAGAIN},
    {ERROR_CONNECTION_REFUSED, OE_ECONNREFUSED},
    {ERROR_CRC, OE_EIO},
    {ERROR_DEVICE_DOOR_OPEN, OE_EIO},
    {ERROR_DEVICE_IN_USE, OE_EAGAIN},
    {ERROR_DEVICE_REQUIRES_CLEANING, OE_EIO},
    {ERROR_DEV_NOT_EXIST, OE_ENOENT},
    {ERROR_DIRECTORY, OE_ENOTDIR},
    {ERROR_DIR_NOT_EMPTY, OE_ENOTEMPTY},
    {ERROR_DISK_CORRUPT, OE_EIO},
    {ERROR_DISK_FULL, OE_ENOSPC},
    {ERROR_DS_GENERIC_ERROR, OE_EIO},
    {ERROR_DUP_NAME, OE_ENOTUNIQ},
    {ERROR_EAS_DIDNT_FIT, OE_ENOSPC},
    {ERROR_EAS_NOT_SUPPORTED, OE_ENOTSUP},
    {ERROR_EA_LIST_INCONSISTENT, OE_EINVAL},
    {ERROR_EA_TABLE_FULL, OE_ENOSPC},
    {ERROR_END_OF_MEDIA, OE_ENOSPC},
    {ERROR_EOM_OVERFLOW, OE_EIO},
    {ERROR_EXE_MACHINE_TYPE_MISMATCH, OE_ENOEXEC},
    {ERROR_EXE_MARKED_INVALID, OE_ENOEXEC},
    {ERROR_FILEMARK_DETECTED, OE_EIO},
    {ERROR_FILENAME_EXCED_RANGE, OE_ENAMETOOLONG},
    {ERROR_FILE_CORRUPT, OE_EEXIST},
    {ERROR_FILE_EXISTS, OE_EEXIST},
    {ERROR_FILE_INVALID, OE_ENXIO},
    {ERROR_FILE_NOT_FOUND, OE_ENOENT},
    {ERROR_HANDLE_DISK_FULL, OE_ENOSPC},
    {ERROR_HANDLE_EOF, OE_ENODATA},
    {ERROR_INVALID_ADDRESS, OE_EINVAL},
    {ERROR_INVALID_AT_INTERRUPT_TIME, OE_EINTR},
    {ERROR_INVALID_BLOCK_LENGTH, OE_EIO},
    {ERROR_INVALID_DATA, OE_EINVAL},
    {ERROR_INVALID_DRIVE, OE_ENODEV},
    {ERROR_INVALID_EA_NAME, OE_EINVAL},
    {ERROR_INVALID_EXE_SIGNATURE, OE_ENOEXEC},
    {ERROR_INVALID_FUNCTION, OE_EBADRQC},
    {ERROR_INVALID_HANDLE, OE_EBADF},
    {ERROR_INVALID_NAME, OE_ENOENT},
    {ERROR_INVALID_PARAMETER, OE_EINVAL},
    {ERROR_INVALID_SIGNAL_NUMBER, OE_EINVAL},
    {ERROR_IOPL_NOT_ENABLED, OE_ENOEXEC},
    {ERROR_IO_DEVICE, OE_EIO},
    {ERROR_IO_INCOMPLETE, OE_EAGAIN},
    {ERROR_IO_PENDING, OE_EAGAIN},
    {ERROR_LOCK_VIOLATION, OE_EBUSY},
    {ERROR_MAX_THRDS_REACHED, OE_EAGAIN},
    {ERROR_META_EXPANSION_TOO_LONG, OE_EINVAL},
    {ERROR_MOD_NOT_FOUND, OE_ENOENT},
    {ERROR_MORE_DATA, OE_EMSGSIZE},
    {ERROR_NEGATIVE_SEEK, OE_EINVAL},
    {ERROR_NETNAME_DELETED, OE_ENOENT},
    {ERROR_NOACCESS, OE_EFAULT},
    {ERROR_NONE_MAPPED, OE_EINVAL},
    {ERROR_NONPAGED_SYSTEM_RESOURCES, OE_EAGAIN},
    {ERROR_NOT_CONNECTED, OE_ENOLINK},
    {ERROR_NOT_ENOUGH_MEMORY, OE_ENOMEM},
    {ERROR_NOT_ENOUGH_QUOTA, OE_EIO},
    {ERROR_NOT_OWNER, OE_EPERM},
    {ERROR_NOT_READY, OE_ENOMEDIUM},
    {ERROR_NOT_SAME_DEVICE, OE_EXDEV},
    {ERROR_NOT_SUPPORTED, OE_ENOSYS},
    {ERROR_NO_DATA, OE_EPIPE},
    {ERROR_NO_DATA_DETECTED, OE_EIO},
    {ERROR_NO_MEDIA_IN_DRIVE, OE_ENOMEDIUM},
    {ERROR_NO_MORE_FILES, OE_ENFILE},
    {ERROR_NO_MORE_ITEMS, OE_ENFILE},
    {ERROR_NO_MORE_SEARCH_HANDLES, OE_ENFILE},
    {ERROR_NO_PROC_SLOTS, OE_EAGAIN},
    {ERROR_NO_SIGNAL_SENT, OE_EIO},
    {ERROR_NO_SYSTEM_RESOURCES, OE_EFBIG},
    {ERROR_NO_TOKEN, OE_EINVAL},
    {ERROR_OPEN_FAILED, OE_EIO},
    {ERROR_OPEN_FILES, OE_EAGAIN},
    {ERROR_OUTOFMEMORY, OE_ENOMEM},
    {ERROR_PAGED_SYSTEM_RESOURCES, OE_EAGAIN},
    {ERROR_PAGEFILE_QUOTA, OE_EAGAIN},
    {ERROR_PATH_NOT_FOUND, OE_ENOENT},
    {ERROR_PIPE_BUSY, OE_EBUSY},
    {ERROR_PIPE_CONNECTED, OE_EBUSY},
    {ERROR_PIPE_LISTENING, OE_ECOMM},
    {ERROR_PIPE_NOT_CONNECTED, OE_ECOMM},
    {ERROR_POSSIBLE_DEADLOCK, OE_EDEADLOCK},
    {ERROR_PRIVILEGE_NOT_HELD, OE_EPERM},
    {ERROR_PROCESS_ABORTED, OE_EFAULT},
    {ERROR_PROC_NOT_FOUND, OE_ESRCH},
    {ERROR_REM_NOT_LIST, OE_ENONET},
    {ERROR_SECTOR_NOT_FOUND, OE_EINVAL},
    {ERROR_SEEK, OE_EINVAL},
    {ERROR_SERVICE_REQUEST_TIMEOUT, OE_EBUSY},
    {ERROR_SETMARK_DETECTED, OE_EIO},
    {ERROR_SHARING_BUFFER_EXCEEDED, OE_ENOLCK},
    {ERROR_SHARING_VIOLATION, OE_EBUSY},
    {ERROR_SIGNAL_PENDING, OE_EBUSY},
    {ERROR_SIGNAL_REFUSED, OE_EIO},
    {ERROR_SXS_CANT_GEN_ACTCTX, OE_ELIBBAD},
    {ERROR_THREAD_1_INACTIVE, OE_EINVAL},
    {ERROR_TIMEOUT, OE_EBUSY},
    {ERROR_TOO_MANY_LINKS, OE_EMLINK},
    {ERROR_TOO_MANY_OPEN_FILES, OE_EMFILE},
    {ERROR_UNEXP_NET_ERR, OE_EIO},
    {ERROR_WAIT_NO_CHILDREN, OE_ECHILD},
    {ERROR_WORKING_SET_QUOTA, OE_EAGAIN},
    {ERROR_WRITE_PROTECT, OE_EROFS},
    {0, 0}};

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

static int _winerr_to_errno(int winerr)
{
    return _do_lookup(winerr, OE_EINVAL, winerr2errno);
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
    OE_UNUSED(mode);

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
    if ((count & UINT_MAX) != count)
        _set_errno(OE_EINVAL);

    return _read((int)fd, buf, (unsigned int)count);
}

ssize_t oe_syscall_write_ocall(oe_host_fd_t fd, const void* buf, size_t count)
{
    if ((count & UINT_MAX) != count)
        _set_errno(OE_EINVAL);

    return _write((int)fd, buf, (unsigned int)count);
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
    OE_UNUSED(fd);
    OE_UNUSED(offset);
    OE_UNUSED(whence);

    PANIC;
}

int oe_syscall_close_ocall(oe_host_fd_t fd)
{
    return _close((int)fd);
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
    OE_UNUSED(pathname);

    PANIC;
}

int oe_syscall_readdir_ocall(uint64_t dirp, struct oe_dirent* entry)
{
    OE_UNUSED(dirp);
    OE_UNUSED(entry);

    PANIC;
}

void oe_syscall_rewinddir_ocall(uint64_t dirp)
{
    OE_UNUSED(dirp);

    PANIC;
}

int oe_syscall_closedir_ocall(uint64_t dirp)
{
    OE_UNUSED(dirp);

    PANIC;
}

int oe_syscall_stat_ocall(const char* pathname, struct oe_stat* buf)
{
    OE_UNUSED(pathname);
    OE_UNUSED(buf);

    PANIC;
}

int oe_syscall_access_ocall(const char* pathname, int mode)
{
    OE_UNUSED(pathname);
    OE_UNUSED(mode);

    PANIC;
}

int oe_syscall_link_ocall(const char* oldpath, const char* newpath)
{
    OE_UNUSED(oldpath);
    OE_UNUSED(newpath);

    PANIC;
}

int oe_syscall_unlink_ocall(const char* pathname)
{
    OE_UNUSED(pathname);

    PANIC;
}

int oe_syscall_rename_ocall(const char* oldpath, const char* newpath)
{
    OE_UNUSED(oldpath);
    OE_UNUSED(newpath);

    PANIC;
}

int oe_syscall_truncate_ocall(const char* pathname, oe_off_t length)
{
    OE_UNUSED(pathname);
    OE_UNUSED(length);

    PANIC;
}

int oe_syscall_mkdir_ocall(const char* pathname, oe_mode_t mode)
{
    OE_UNUSED(pathname);
    OE_UNUSED(mode);

    PANIC;
}

int oe_syscall_rmdir_ocall(const char* pathname)
{
    OE_UNUSED(pathname);

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
        if (socket_fd)
        {
            socket_fd->magic = OE_SOCKET_FD_MAGIC;
            socket_fd->socket = sock;
            fd = (oe_host_fd_t)socket_fd;
        }
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
        // Duplicate socket
        WSAPROTOCOL_INFO protocolInfo;
        int ret = WSADuplicateSocket(
            old_socket_fd->socket, GetCurrentProcessId(), &protocolInfo);
        if (ret == SOCKET_ERROR)
        {
            _set_errno(_winsockerr_to_errno(WSAGetLastError()));
        }

        SOCKET sock = WSASocket(
            protocolInfo.iAddressFamily,
            protocolInfo.iSocketType,
            protocolInfo.iProtocol,
            &protocolInfo,
            0,
            0);
        if (sock == INVALID_SOCKET)
        {
            _set_errno(_winsockerr_to_errno(WSAGetLastError()));
        }

        return _make_socket_fd(sock);
    }

    return -1;
}

static int _wsa_startup()
{
    static int64_t wsa_init_done = FALSE;
    WSADATA wsaData;
    int ret = 0;

    if (oe_atomic_compare_and_swap(
            (volatile int64_t*)&wsa_init_done, (int64_t)0, (int64_t)1))
    {
        ret = WSAStartup(2, &wsaData);
        if (ret != 0)
            goto done;
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
    OE_UNUSED(domain);
    OE_UNUSED(type);
    OE_UNUSED(protocol);
    OE_UNUSED(sv_out);

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
    OE_UNUSED(sockfd);
    OE_UNUSED(msg_name);
    OE_UNUSED(msg_namelen);
    OE_UNUSED(msg_namelen_out);
    OE_UNUSED(msg_iov_buf);
    OE_UNUSED(msg_iovlen);
    OE_UNUSED(msg_iov_buf_size);
    OE_UNUSED(msg_control);
    OE_UNUSED(msg_controllen);
    OE_UNUSED(msg_controllen_out);
    OE_UNUSED(flags);

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
    OE_UNUSED(sockfd);
    OE_UNUSED(msg_name);
    OE_UNUSED(msg_namelen);
    OE_UNUSED(msg_iov_buf);
    OE_UNUSED(msg_iovlen);
    OE_UNUSED(msg_iov_buf_size);
    OE_UNUSED(msg_control);
    OE_UNUSED(msg_controllen);
    OE_UNUSED(flags);

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
        (int*)&addrlen_in);
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
    OE_UNUSED(fd);
    OE_UNUSED(iov_buf);
    OE_UNUSED(iovcnt);
    OE_UNUSED(iov_buf_size);

    PANIC;
}

ssize_t oe_syscall_sendv_ocall(
    oe_host_fd_t fd,
    const void* iov_buf,
    int iovcnt,
    size_t iov_buf_size)
{
    OE_UNUSED(fd);
    OE_UNUSED(iov_buf);
    OE_UNUSED(iovcnt);
    OE_UNUSED(iov_buf_size);

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
    OE_UNUSED(fd);
    OE_UNUSED(arg);
    OE_UNUSED(argsize);
    OE_UNUSED(argout);

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
    OE_UNUSED(sockfd);
    OE_UNUSED(addr);
    OE_UNUSED(addrlen_in);
    OE_UNUSED(addrlen_out);

    PANIC;
}

int oe_syscall_getpeername_ocall(
    oe_host_fd_t sockfd,
    struct oe_sockaddr* addr,
    oe_socklen_t addrlen_in,
    oe_socklen_t* addrlen_out)
{
    OE_UNUSED(sockfd);
    OE_UNUSED(addr);
    OE_UNUSED(addrlen_in);
    OE_UNUSED(addrlen_out);

    PANIC;
}

int oe_syscall_shutdown_sockets_device_ocall(oe_host_fd_t sockfd)
{
    OE_UNUSED(sockfd);

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
    OE_UNUSED(pid);
    OE_UNUSED(signum);

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
    OE_UNUSED(sa);
    OE_UNUSED(salen);
    OE_UNUSED(host);
    OE_UNUSED(hostlen);
    OE_UNUSED(serv);
    OE_UNUSED(servlen);
    OE_UNUSED(flags);

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
    OE_UNUSED(flags);

    PANIC;
}

int oe_syscall_epoll_wait_ocall(
    int64_t epfd,
    struct oe_epoll_event* events,
    unsigned int maxevents,
    int timeout)
{
    OE_UNUSED(epfd);
    OE_UNUSED(events);
    OE_UNUSED(maxevents);
    OE_UNUSED(timeout);

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
    OE_UNUSED(epfd);
    OE_UNUSED(op);
    OE_UNUSED(fd);
    OE_UNUSED(event);

    PANIC;
}

int oe_syscall_epoll_close_ocall(oe_host_fd_t epfd)
{
    OE_UNUSED(epfd);

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
    OE_UNUSED(host_fds);
    OE_UNUSED(nfds);
    OE_UNUSED(timeout);

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
    OE_UNUSED(pid);

    PANIC;
}

int oe_syscall_getgroups_ocall(size_t size, unsigned int* list)
{
    OE_UNUSED(size);
    OE_UNUSED(list);

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
    int ret = -1;

    if (!buf)
    {
        _set_errno(OE_EINVAL);
        goto done;
    }

    // Get domain name
    DWORD size = sizeof(buf->domainname);
    if (!GetComputerNameEx(ComputerNameDnsDomain, buf->domainname, &size))
    {
        _set_errno(_winerr_to_errno(GetLastError()));
        goto done;
    }

    // Get hostname
    size = sizeof(buf->nodename);
    if (!GetComputerNameEx(ComputerNameDnsHostname, buf->nodename, &size))
    {
        _set_errno(_winerr_to_errno(GetLastError()));
        goto done;
    }

    // Based on
    // https://docs.microsoft.com/en-us/windows/win32/sysinfo/getting-the-system-version
    // OE SDK is supported only on WindowsServer and Win10
    if (IsWindowsServer())
    {
        sprintf(buf->sysname, "WindowsServer");
        sprintf(buf->version, "2016OrAbove");
    }
    else if (IsWindows10OrGreater())
    {
        sprintf(buf->sysname, "Windows10OrGreater");
        sprintf(buf->version, "10OrAbove");
    }

    ret = 0;

done:
    return ret;
}

/*
**==============================================================================
**
** nanosleep():
**
**==============================================================================
*/

int oe_syscall_nanosleep_ocall(struct oe_timespec* req, struct oe_timespec* rem)
{
    uint64_t milliseconds = 0;

    if (!req)
    {
        _set_errno(OE_EINVAL);
        return -1;
    }

    milliseconds += req->tv_sec * 1000UL;
    milliseconds += req->tv_nsec / 1000000UL;

    while (milliseconds > UINT_MAX)
    {
        Sleep(UINT_MAX);
        milliseconds -= UINT_MAX;
    }

    Sleep((DWORD)milliseconds);

    // Windows sleep is not interruptable by hardware exception handling. Just
    // wait the whole time and zero rem.
    if (rem)
        memset(rem, 0, sizeof(*rem));

    _set_errno(0);
    return 0;
}
