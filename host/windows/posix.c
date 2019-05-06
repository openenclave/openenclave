// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

/*
**==============================================================================
**
** windows/posix.c:
**
**     This file implements POSIX OCALLs for Windows. Most of these are stubs
**     which are still under development.
**
**==============================================================================
*/

#include <io.h>
#include <stdint.h>
#include <sys/stat.h>
#include "windows.h"

#include "posix_u.h"

#include "openenclave/corelibc/errno.h"
#include "openenclave/corelibc/fcntl.h"

#undef errno
static __declspec(thread) int errno = 0;

static BOOL _winsock_inited = 0;

// Declare these here rather than deal with header file issues.

int _wmkdir(const wchar_t* dirname);

int _wrmdir(const wchar_t* dirname);

/*
**==============================================================================
**
** Errno/GetLastError conversion
**
**==============================================================================
*/

struct errno_tab_entry
{
    DWORD winerr;
    int error_no;
};

static struct errno_tab_entry errno2winerr[] = {
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

static DWORD _errno_to_winerr(int errno)
{
    struct errno_tab_entry* pent = errno2winerr;

    do
    {
        if (pent->error_no == errno)
        {
            return pent->winerr;
        }
        pent++;

    } while (pent->error_no != 0);

    return ERROR_INVALID_PARAMETER;
}

static int _winerr_to_errno(DWORD winerr)
{
    struct errno_tab_entry* pent = errno2winerr;

    do
    {
        if (pent->winerr == winerr)
        {
            return pent->error_no;
        }
        pent++;

    } while (pent->winerr != 0);

    return OE_EINVAL;
}

static struct errno_tab_entry errno2winsockerr[] = {
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
    {WSAEDISCON, 199},
    {WSAEPROCLIM, 200},
    {WSASYSNOTREADY, 201}, // Made up number but close to adjacent
    {WSAVERNOTSUPPORTED, 202},
    {WSANOTINITIALISED, 203},
    {0, 0}};

static DWORD _errno_to_winsockerr(int errno)
{
    struct errno_tab_entry* pent = errno2winsockerr;

    do
    {
        if (pent->error_no == errno)
        {
            return pent->winerr;
        }
        pent++;

    } while (pent->error_no != 0);

    return ERROR_INVALID_PARAMETER;
}

static int _winsockerr_to_errno(DWORD winsockerr)
{
    struct errno_tab_entry* pent = errno2winsockerr;

    do
    {
        if (pent->winerr == winsockerr)
        {
            return pent->error_no;
        }
        pent++;

    } while (pent->winerr != 0);

    return OE_EINVAL;
}

/*
**==============================================================================
**
** Local definitions.
**
**==============================================================================
*/
static BOOL _winsock_init()
{
    int ret = -1;
    static WSADATA startup_data = {0};

    // Initialize Winsock
    ret = WSAStartup(MAKEWORD(2, 2), &startup_data);
    if (ret != 0)
    {
        printf("WSAStartup failed: %d\n", ret);
        return FALSE;
    }
    return TRUE;
}

__declspec(noreturn) static void _panic(
    const char* file,
    unsigned int line,
    const char* function)
{
    fprintf(stderr, "%s(%u): %s(): panic\n", file, line, function);
    abort();
}

#define PANIC _panic(__FILE__, __LINE__, __FUNCTION__);

/*
**==============================================================================
**
** File and directory I/O:
**
**==============================================================================
*/

oe_host_fd_t oe_posix_open_ocall(
    const char* pathname,
    int flags,
    oe_mode_t mode)
{
    oe_host_fd_t ret = -1;

    if (strcmp(pathname, "/dev/stdin") == 0)
    {
        if ((flags & 0x00000003) != OE_O_RDONLY)
        {
            errno = OE_EINVAL;
            goto done;
        }

        ret = (oe_host_fd_t)GetStdHandle(STD_INPUT_HANDLE);
    }
    else if (strcmp(pathname, "/dev/stdout") == 0)
    {
        if ((flags & 0x00000003) != OE_O_WRONLY)
        {
            errno = OE_EINVAL;
            goto done;
        }

        ret = (oe_host_fd_t)GetStdHandle(STD_OUTPUT_HANDLE);
    }
    else if (strcmp(pathname, "/dev/stderr") == 0)
    {
        if ((flags & 0x00000003) != OE_O_WRONLY)
        {
            errno = OE_EINVAL;
            goto done;
        }

        ret = (oe_host_fd_t)GetStdHandle(STD_ERROR_HANDLE);
    }
    else
    {
        DWORD desired_access = 0;
        DWORD share_mode = 0;
        DWORD create_dispos = OPEN_EXISTING;
        DWORD file_flags = (FILE_ATTRIBUTE_NORMAL | FILE_FLAG_POSIX_SEMANTICS);

        int nLen = MultiByteToWideChar(CP_UTF8, 0, pathname, -1, NULL, 0);
        WCHAR* wpathname = (WCHAR*)(calloc((nLen + 1) * sizeof(WCHAR), 1));
        MultiByteToWideChar(CP_UTF8, 0, pathname, -1, wpathname, nLen);

        if ((flags & OE_O_DIRECTORY) != 0)
        {
            file_flags |=
                FILE_FLAG_BACKUP_SEMANTICS; // This will make a directory. Not
                                            // obvious but there it is
        }

        /* Open flags are neither a bitmask nor a sequence, so switching or
         * maskign don't really work. */

        if ((flags & OE_O_CREAT) != 0)
        {
            create_dispos = OPEN_ALWAYS;
        }
        else
        {
            if ((flags & OE_O_TRUNC) != 0)
            {
                create_dispos = TRUNCATE_EXISTING;
            }
            else if ((flags & OE_O_APPEND) != 0)
            {
                desired_access = FILE_APPEND_DATA;
            }
        }

        const int ACCESS_FLAGS = 0x3; // Covers rdonly, wronly rdwr
        switch (flags & ACCESS_FLAGS)
        {
            case OE_O_RDONLY: // 0
                desired_access |= GENERIC_READ;
                share_mode = FILE_SHARE_READ;
                break;

            case OE_O_WRONLY: // 1
                desired_access |= GENERIC_WRITE;
                share_mode = FILE_SHARE_WRITE;
                break;

            case OE_O_RDWR: // 2 or 3
                desired_access |= GENERIC_READ | GENERIC_WRITE;
                share_mode = FILE_SHARE_READ | FILE_SHARE_WRITE;
                break;

            default:
                ret = -1;
                errno = OE_EINVAL;
                goto done;
                break;
        }

        // 2do: mode

        HANDLE h = CreateFileW(
            wpathname,
            desired_access,
            share_mode,
            NULL,
            create_dispos,
            file_flags,
            NULL);
        if (h == INVALID_HANDLE_VALUE)
        {
            errno = _winerr_to_errno(GetLastError());
            goto done;
        }

        ret = (oe_host_fd_t)h;
        _wchmod(wpathname, mode);
        if (wpathname)
        {
            free(wpathname);
        }
    }

done:
    return ret;
}

ssize_t oe_posix_read_ocall(oe_host_fd_t fd, void* buf, size_t count)
{
    ssize_t ret = -1;
    DWORD bytes_returned = 0;

    // Convert fd 0, 1, 2 as needed
    switch (fd)
    {
        case 0:
            fd = (oe_host_fd_t)GetStdHandle(STD_INPUT_HANDLE);
            break;

        case 1:
            errno = OE_EBADF;
            goto done;

        case 2:
            errno = OE_EBADF;
            goto done;

        default:
            break;
    }

    if (!ReadFile((HANDLE)fd, buf, (DWORD)count, &bytes_returned, NULL))
    {
        errno = _winerr_to_errno(GetLastError());
        goto done;
    }

    ret = (ssize_t)bytes_returned;

done:
    return ret;
}

ssize_t oe_posix_write_ocall(oe_host_fd_t fd, const void* buf, size_t count)
{
    ssize_t ret = -1;
    DWORD bytes_written = 0;

    // Convert fd 0, 1, 2 as needed
    switch (fd)
    {
        case 0:
            // Error. You cant write to stdin
            errno = OE_EBADF;
            goto done;

        case 1:
            fd = (oe_host_fd_t)GetStdHandle(STD_OUTPUT_HANDLE);
            break;

        case 2:
            fd = (oe_host_fd_t)GetStdHandle(STD_ERROR_HANDLE);
            break;

        default:
            break;
    }

    if (!WriteFile((HANDLE)fd, buf, (DWORD)count, &bytes_written, NULL))
    {
        errno = _winerr_to_errno(GetLastError());
        goto done;
    }

    ret = (ssize_t)bytes_written;

done:
    return ret;
}

oe_off_t oe_posix_lseek_ocall(oe_host_fd_t fd, oe_off_t offset, int whence)
{
    ssize_t ret = -1;
    DWORD byteswritten = 0;
    LARGE_INTEGER new_offset = {0};

    new_offset.QuadPart = offset;
    if (SetFilePointerEx(
            (HANDLE)fd, new_offset, (PLARGE_INTEGER)&new_offset, whence))
    {
        errno = _winerr_to_errno(GetLastError());
        goto done;
    }

    ret = (oe_off_t)new_offset.QuadPart;

done:
    return ret;
}

int oe_posix_close_ocall(oe_host_fd_t fd)
{
    if (!CloseHandle((HANDLE)fd))
    {
        errno = OE_EINVAL;
        return -1;
    }
    return 0;
}

oe_host_fd_t oe_posix_dup_ocall(oe_host_fd_t oldfd)
{
    oe_host_fd_t ret = -1;
    oe_host_fd_t newfd = -1;
    char pibuff[1024] = {0};
    struct _WSAPROTOCOL_INFOA* pi = (struct _WSAPROTOCOL_INFOA*)pibuff;

    // Convert fd 0, 1, 2 as needed
    switch (oldfd)
    {
        case 0:
            oldfd = (oe_host_fd_t)GetStdHandle(STD_INPUT_HANDLE);
            break;

        case 1:
            oldfd = (oe_host_fd_t)GetStdHandle(STD_OUTPUT_HANDLE);
            break;

        case 2:
            oldfd = (oe_host_fd_t)GetStdHandle(STD_ERROR_HANDLE);
            break;

        default:
            break;
    }

    ret = WSADuplicateSocketA((SOCKET)oldfd, GetCurrentProcessId(), pi);
    if (ret < 0)
    {
        int sockerr = WSAGetLastError();

        if (sockerr != WSAENOTSOCK)
        {
            errno = _winsockerr_to_errno(WSAGetLastError());
            goto done;
        }
    }
    else
    {
        newfd = WSASocketA(-1, -1, -1, pi, 0, 0);
        ret = newfd;
        errno = 0;
        goto done;
    }

    if (!DuplicateHandle(
            GetCurrentProcess(),
            (HANDLE)oldfd,
            GetCurrentProcess(),
            (HANDLE*)&ret,
            0,
            FALSE,
            DUPLICATE_SAME_ACCESS))
    {
        errno = _winerr_to_errno(GetLastError());
        goto done;
    }

done:
    return ret;
}

uint64_t oe_posix_opendir_ocall(const char* name)
{
    PANIC;
}

int oe_posix_readdir_ocall(
    uint64_t dirp,
    uint64_t* d_ino,
    int64_t* d_off,
    uint16_t* d_reclen,
    uint8_t* d_type,
    char* d_name,
    size_t d_namelen)
{
    PANIC;
}

void oe_posix_rewinddir_ocall(uint64_t dirp)
{
    PANIC;
}

int oe_posix_closedir_ocall(uint64_t dirp)
{
    PANIC;
}

int oe_posix_stat_ocall(const char* pathname, struct oe_stat* buf)
{
    int ret = -1;
    int nLen = MultiByteToWideChar(CP_UTF8, 0, pathname, -1, NULL, 0);
    WCHAR* wpathname = (WCHAR*)(calloc((nLen + 1) * sizeof(WCHAR), 1));
    MultiByteToWideChar(CP_UTF8, 0, pathname, -1, wpathname, nLen);

    struct _stat64 winstat = {0};

    ret = _wstat64(wpathname, &winstat);
    if (ret < 0)
    {
        // How do we get to  wstat's error

        errno = _winerr_to_errno(GetLastError());
        goto done;
    }

#undef st_atime
#undef st_mtime
#undef st_ctime

    buf->st_dev = winstat.st_dev;
    buf->st_ino = winstat.st_ino;
    buf->st_mode = winstat.st_mode;
    buf->st_nlink = winstat.st_nlink;
    buf->st_uid = winstat.st_uid;
    buf->st_gid = winstat.st_gid;
    buf->st_rdev = winstat.st_rdev;
    buf->st_size = winstat.st_size;
    buf->st_atim.tv_sec = winstat.st_atime;
    buf->st_mtim.tv_sec = winstat.st_mtime;
    buf->st_ctim.tv_sec = winstat.st_ctime;

done:

    if (wpathname)
    {
        free(wpathname);
    }

    return ret;
}

int oe_posix_access_ocall(const char* pathname, int mode)
{
    PANIC;
}

int oe_posix_link_ocall(const char* oldpath, const char* newpath)
{
    PANIC;
}

int oe_posix_unlink_ocall(const char* pathname)
{
    PANIC;
}

int oe_posix_rename_ocall(const char* oldpath, const char* newpath)
{
    PANIC;
}

int oe_posix_truncate_ocall(const char* path, oe_off_t length)
{
    PANIC;
}

int oe_posix_mkdir_ocall(const char* pathname, oe_mode_t mode)
{
    int ret = -1;
    int nLen = MultiByteToWideChar(CP_UTF8, 0, pathname, -1, NULL, 0);
    WCHAR* wpathname = (WCHAR*)(calloc((nLen + 1) * sizeof(WCHAR), 1));
    MultiByteToWideChar(CP_UTF8, 0, pathname, -1, wpathname, nLen);

    ret = _wmkdir(wpathname);
    if (ret < 0)
    {
        errno = _winerr_to_errno(GetLastError());
        goto done;
    }

done:
    if (wpathname)
    {
        free(wpathname);
    }
    return ret;
}

int oe_posix_rmdir_ocall(const char* pathname)
{
    int ret = -1;
    int nLen = MultiByteToWideChar(CP_UTF8, 0, pathname, -1, NULL, 0);
    WCHAR* wpathname = (WCHAR*)(calloc((nLen + 1) * sizeof(WCHAR), 1));
    MultiByteToWideChar(CP_UTF8, 0, pathname, -1, wpathname, nLen);

    ret = _wrmdir(wpathname);
    if (ret < 0)
    {
        errno = _winerr_to_errno(GetLastError());
        goto done;
    }

done:
    if (wpathname)
    {
        free(wpathname);
    }
    return ret;
}

/*
**==============================================================================
**
** Socket I/O:
**
**==============================================================================
*/
int WSAStartup(_In_ WORD wVersionRequested, _Out_ LPWSADATA lpWSAData);

oe_host_fd_t oe_posix_socket_ocall(int domain, int type, int protocol)
{
    oe_host_fd_t ret = -1;
    HANDLE h = INVALID_HANDLE_VALUE;

    if (!_winsock_inited)
    {
        if (!_winsock_init())
        {
            errno = OE_ENOTSOCK;
        }
    }

    // We are hoping, and think it is true, that accept in winsock returns the
    // same error returns as accept everywhere else
    ret = socket(domain, type, protocol);
    if (ret == SOCKET_ERROR)
    {
        errno = _winsockerr_to_errno(WSAGetLastError());
    }

    return ret;
}

int oe_posix_socketpair_ocall(
    int domain,
    int type,
    int protocol,
    oe_host_fd_t sv_out[2])
{
    PANIC;
}

int oe_posix_connect_ocall(
    oe_host_fd_t sockfd,
    const struct oe_sockaddr* addr,
    oe_socklen_t addrlen)
{
    int ret = -1;

    SOCKADDR_IN sadd = *(PSOCKADDR_IN)addr;
    printf(
        "sock addr = %d %d %d %d\n",
        sadd.sin_addr.S_un.S_un_b.s_b1,
        sadd.sin_addr.S_un.S_un_b.s_b2,
        sadd.sin_addr.S_un.S_un_b.s_b3,
        sadd.sin_addr.S_un.S_un_b.s_b4);

    ret = connect((SOCKET)sockfd, (const struct sockaddr*)addr, (int)addrlen);
    if (ret == SOCKET_ERROR)
    {
        errno = _winsockerr_to_errno(WSAGetLastError());
    }
    return ret;
}

oe_host_fd_t oe_posix_accept_ocall(
    oe_host_fd_t sockfd,
    struct oe_sockaddr* addr,
    oe_socklen_t addrlen_in,
    oe_socklen_t* addrlen_out)
{
    oe_host_fd_t ret = -1;

    // We are hoping, and think it is true, that accept in winsock returns the
    // same error returns as accept everywhere else
    ret = accept((SOCKET)sockfd, (struct sockaddr*)addr, (int*)addrlen_out);
    if (ret == SOCKET_ERROR)
    {
        errno = _winsockerr_to_errno(WSAGetLastError());
    }

    return ret;
}

int oe_posix_bind_ocall(
    oe_host_fd_t sockfd,
    const struct oe_sockaddr* addr,
    oe_socklen_t addrlen)
{
    oe_host_fd_t ret = -1;

    ret = bind((SOCKET)sockfd, (struct sockaddr*)addr, (int)addrlen);
    if (ret == SOCKET_ERROR)
    {
        errno = _winsockerr_to_errno(WSAGetLastError());
    }

    return ret;
}

int oe_posix_listen_ocall(oe_host_fd_t sockfd, int backlog)
{
    oe_host_fd_t ret = -1;

    ret = listen((SOCKET)sockfd, backlog);
    if (ret == SOCKET_ERROR)
    {
        errno = _winsockerr_to_errno(WSAGetLastError());
    }
}

ssize_t oe_posix_recvmsg_ocall(
    oe_host_fd_t sockfd,
    void* msg_name,
    oe_socklen_t msg_namelen,
    oe_socklen_t* msg_namelen_out,
    void* msg_buf,
    size_t msg_buflen,
    void* msg_control,
    size_t msg_controllen,
    size_t* msg_controllen_out,
    int flags)
{
    PANIC;
}

ssize_t oe_posix_sendmsg_ocall(
    oe_host_fd_t sockfd,
    const void* msg_name,
    oe_socklen_t msg_namelen,
    const void* msg_buf,
    size_t msg_buflen,
    const void* msg_control,
    size_t msg_controllen,
    int flags)
{
    PANIC;
}

ssize_t oe_posix_recv_ocall(
    oe_host_fd_t sockfd,
    void* buf,
    size_t len,
    int flags)
{
    oe_host_fd_t ret = -1;

    ret = recv((SOCKET)sockfd, buf, len, flags);
    if (ret == SOCKET_ERROR)
    {
        errno = _winsockerr_to_errno(WSAGetLastError());
    }

    return ret;
}

ssize_t oe_posix_recvfrom_ocall(
    oe_host_fd_t sockfd,
    void* buf,
    size_t len,
    int flags,
    struct oe_sockaddr* src_addr,
    oe_socklen_t addrlen_in,
    oe_socklen_t* addrlen_out)
{
    PANIC;
}

ssize_t oe_posix_send_ocall(
    oe_host_fd_t sockfd,
    const void* buf,
    size_t len,
    int flags)
{
    oe_host_fd_t ret = -1;

    ret = send((SOCKET)sockfd, buf, len, flags);
    if (ret == SOCKET_ERROR)
    {
        errno = _winsockerr_to_errno(WSAGetLastError());
    }

    return ret;
}

ssize_t oe_posix_sendto_ocall(
    oe_host_fd_t sockfd,
    const void* buf,
    size_t len,
    int flags,
    const struct oe_sockaddr* src_addr,
    oe_socklen_t addrlen)
{
    oe_host_fd_t ret = -1;

    ret = sendto((SOCKET)sockfd, buf, len, flags, src_addr, addrlen);
    if (ret == SOCKET_ERROR)
    {
        errno = _winsockerr_to_errno(WSAGetLastError());
    }

    return ret;
}

int oe_posix_shutdown_ocall(oe_host_fd_t sockfd, int how)
{
    PANIC;
}

int oe_posix_fcntl_ocall(oe_host_fd_t fd, int cmd, uint64_t arg)
{
    PANIC;
}

int oe_posix_setsockopt_ocall(
    oe_host_fd_t sockfd,
    int level,
    int optname,
    const void* optval,
    oe_socklen_t optlen)
{
    oe_host_fd_t ret = -1;

    // ATTN: I'm trusting setsockopt not to make funny here. IT may or may not.
    // If it does, we will have to translate the args.
    ret = setsockopt((SOCKET)sockfd, level, optname, optval, optlen);
    if (ret == SOCKET_ERROR)
    {
        errno = _winsockerr_to_errno(WSAGetLastError());
    }

    return ret;
}

int oe_posix_getsockopt_ocall(
    oe_host_fd_t sockfd,
    int level,
    int optname,
    void* optval,
    oe_socklen_t optlen_in,
    oe_socklen_t* optlen_out)
{
    oe_host_fd_t ret = -1;

    // ATTN: I'm trusting getsockopt not to make funny here. IT may or may not.
    // If it does, we will have to translate the args.
    ret = getsockopt(
        (SOCKET)sockfd, level, optname, optval, optlen_in, optlen_out);
    if (ret == SOCKET_ERROR)
    {
        errno = _winsockerr_to_errno(WSAGetLastError());
    }

    return ret;
}

int oe_posix_getsockname_ocall(
    oe_host_fd_t sockfd,
    struct oe_sockaddr* addr,
    oe_socklen_t addrlen_in,
    oe_socklen_t* addrlen_out)
{
    PANIC;
}

int oe_posix_getpeername_ocall(
    oe_host_fd_t sockfd,
    struct oe_sockaddr* addr,
    oe_socklen_t addrlen_in,
    oe_socklen_t* addrlen_out)
{
    PANIC;
}

int oe_posix_shutdown_sockets_device_ocall(oe_host_fd_t sockfd)
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

int oe_posix_kill_ocall(int pid, int signum)
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

uint64_t oe_posix_getaddrinfo_open_ocall(
    const char* node,
    const char* service,
    const struct oe_addrinfo* hints)
{
    PANIC;
}

int oe_posix_getaddrinfo_read_ocall(
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
    PANIC;
}

int oe_posix_getaddrinfo_close_ocall(uint64_t handle_)
{
    PANIC;
}

int oe_posix_getnameinfo_ocall(
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

int oe_posix_shutdown_resolver_device_ocall()
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

oe_host_fd_t oe_posix_epoll_create1_ocall(int flags)
{
    PANIC;
}

int oe_posix_epoll_wait_async_ocall(
    int64_t enclaveid,
    oe_host_fd_t epfd,
    size_t maxevents)
{
    PANIC;
}

int oe_posix_epoll_ctl_add_ocall(
    oe_host_fd_t epfd,
    oe_host_fd_t fd,
    unsigned int event_mask,
    int list_idx,
    int epoll_enclave_fd)
{
    PANIC;
}

int oe_posix_epoll_ctl_del_ocall(oe_host_fd_t epfd, oe_host_fd_t fd)
{
    PANIC;
}

int oe_posix_epoll_ctl_mod_ocall(
    oe_host_fd_t epfd,
    oe_host_fd_t fd,
    unsigned int event_mask,
    int list_idx,
    int enclave_fd)
{
    PANIC;
}

int oe_posix_epoll_close_ocall(oe_host_fd_t fd)
{
    PANIC;
}

int oe_posix_shutdown_polling_device_ocall(oe_host_fd_t fd)
{
    PANIC;
}

int oe_posix_epoll_poll_ocall(
    int64_t enclaveid,
    oe_host_fd_t epfd,
    struct oe_pollfd* fds,
    size_t nfds,
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

int oe_posix_getpid(void)
{
    PANIC;
}

int oe_posix_getppid(void)
{
    PANIC;
}

int oe_posix_getpgrp(void)
{
    PANIC;
}

unsigned int oe_posix_getuid(void)
{
    PANIC;
}

unsigned int oe_posix_geteuid(void)
{
    PANIC;
}

unsigned int oe_posix_getgid(void)
{
    PANIC;
}

unsigned int oe_posix_getegid(void)
{
    PANIC;
}

int oe_posix_getpgid(int pid)
{
    PANIC;
}

int oe_posix_getgroups(size_t size, unsigned int* list)
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

int oe_posix_uname_ocall(struct oe_utsname* buf)
{
    OSVERSIONINFO osvi;

    ZeroMemory(&osvi, sizeof(OSVERSIONINFO));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);

    GetVersionEx(&osvi);

    // 2do: machine
    memset(buf->sysname, 0, __OE_UTSNAME_FIELD_SIZE);
    memset(buf->nodename, 0, __OE_UTSNAME_FIELD_SIZE);
    memset(buf->release, 0, __OE_UTSNAME_FIELD_SIZE);
    memset(buf->version, 0, __OE_UTSNAME_FIELD_SIZE);
    memset(buf->machine, 0, __OE_UTSNAME_FIELD_SIZE);
    memset(buf->__domainname, 0, __OE_UTSNAME_FIELD_SIZE);

    snprintf(
        buf->release,
        __OE_UTSNAME_FIELD_SIZE,
        "%d.%d",
        osvi.dwMajorVersion,
        osvi.dwMinorVersion);
    snprintf(buf->version, __OE_UTSNAME_FIELD_SIZE, "%d", osvi.dwBuildNumber);

    GetEnvironmentVariable("OS", buf->sysname, __OE_UTSNAME_FIELD_SIZE);
    GetEnvironmentVariable(
        "USERDNSDOMAIN", buf->__domainname, __OE_UTSNAME_FIELD_SIZE);
    GetEnvironmentVariable(
        "COMPUTERNAME", buf->nodename, __OE_UTSNAME_FIELD_SIZE);

    return 0;
}
