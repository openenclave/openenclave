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
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

// clang-format off

// stops windows.h including winsock.h
#define _WINSOCKAPI_

#include <aclapi.h>
#include <Shlwapi.h>
#include <windows.h>
#include <winsock2.h>
#include <winternl.h>
#include <Ws2def.h>
#include <Ws2tcpip.h>
#include <VersionHelpers.h>
// clang-format on

#include <openenclave/corelibc/errno.h>
#include <openenclave/internal/atomic.h>
#include <openenclave/internal/syscall/fcntl.h>
#include <openenclave/internal/syscall/dirent.h>
#include <openenclave/internal/syscall/netdb.h>
#include <openenclave/internal/syscall/unistd.h>
#include <openenclave/internal/syscall/sys/stat.h>
#include <openenclave/internal/safecrt.h>
#include <openenclave/internal/raise.h>
#include <openenclave/corelibc/limits.h>
#include "../hostthread.h"
#include "../../common/oe_host_socket.h"
#include "syscall_u.h"

struct WIN_DIR_DATA
{
    HANDLE hFind;
    WIN32_FIND_DATAW FindFileData;
    int dir_offs;
    PCWSTR pdirpath;
};

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
** Syscalls always use UTF-8, but Windows always uses UTF-16LE.
**
**==============================================================================
*/

#define POSIX_DEV_NULL "/dev/null"
#define WIN_DEV_NULL L"NUL"

inline PWSTR _dev_null_to_nul(const char* path)
{
    /* DEV_NULL_PATH is case sensitive on POSIX */
    if (strcmp(path, POSIX_DEV_NULL) == 0)
        return _wcsdup(WIN_DEV_NULL);

    return NULL;
}

inline char* _nul_to_dev_null(PCWSTR path)
{
    /* WIN_NUL_PATH is case insensitive on Windows */
    if (_wcsicmp(path, WIN_DEV_NULL) == 0)
        return _strdup(POSIX_DEV_NULL);

    return NULL;
}

inline void _canonicalize_path_separators(
    char* path,
    size_t path_length,
    char separator)
{
    for (size_t i = 0; i < path_length; i++)
    {
        if (path[i] == '\\' || path[i] == '/')
            path[i] = separator;
    }
}

inline void _windows_to_oe_syscall_volume_root(char* path, size_t path_length)
{
    /* convert "C:" to "/c" */
    if (path && path_length >= 2 && isalpha(path[0]) && path[1] == ':')
    {
        path[1] = tolower(path[0]);
        path[0] = '/';
    }
}

inline bool _is_oe_syscall_path_volume_rooted(const char* path)
{
    /* check for OE-defined volume root at the start of the path e.g. /c/ */
    size_t path_length = strnlen(path, MAX_PATH);
    return (
        path && path_length >= 2 && path[0] == '/' && isalpha(path[1]) &&
        (path[2] == '\0' || path[2] == '/'));
}

inline void _fix_oe_syscall_volume_root(PWSTR path, uint32_t path_length)
{
    /* path_length excludes null terminator */
    if (path && path_length >= 4)
    {
        /* If the original OE syscall path specified a volume root,
         * fix up the resulting canonicalized Windows full path by replacing:
         *  - "C:\x" with "X:\"
         *  - "C:\x\*" with "X:\*" */
        if (iswalpha(path[0]) && path[1] == ':' && path[2] == '\\' &&
            iswalpha(path[3]) && (path[4] == '\0' || path[4] == '\\'))
        {
            path[0] = towupper(path[3]);
            if (path[4] == '\0')
                path[3] = '\0';
            else
            {
                memmove(path + 3, path + 5, (path_length - 5) * sizeof(WCHAR));
                path[path_length - 2] = 0;
            }
        }
    }
}

/* Wrapper for size-and-allocate invocation of GetFullPathNameW */
errno_t _get_full_path_name(
    PCWSTR path,
    uint32_t* outpath_length,
    PWSTR* outpath)
{
    errno_t err = 0;
    DWORD required_length = GetFullPathNameW(path, 0, NULL, NULL);
    if (required_length == 0)
    {
        DWORD winerror = GetLastError();
        OE_TRACE_ERROR("GetFullPathNameW failed with %#x\n", winerror);
        err = _winerr_to_errno(winerror);
        goto done;
    }
    PWSTR outpath_buf = (PWSTR)malloc(required_length * sizeof(WCHAR));
    if (!outpath_buf)
    {
        err = OE_ENOMEM;
        goto done;
    }

    /* Note that the resulting path can be smaller than the originally
     * requested buffer size as GetFullPathName canonicalizes the path after
     * copy */
    *outpath_length =
        GetFullPathNameW(path, required_length, outpath_buf, NULL);

    if (*outpath_length == 0)
    {
        DWORD winerror = GetLastError();
        OE_TRACE_ERROR("GetFullPathNameW failed with %#x\n", winerror);
        err = _winerr_to_errno(winerror);
        goto done;
    }

    *outpath = outpath_buf;

done:
    if (err && outpath_buf)
    {
        free(outpath_buf);
        *outpath = NULL;
    }
    return err;
}

/**
 * _strcpy_to_utf8.
 *
 * This function copies a native (UTF-16LE on Windows) string into a UTF-8
 * buffer. If the buffer is not large enough, the value returned will be larger
 * than ai_canonname_buf_len.
 *
 * @param[out] ai_canonname_buf The buffer to fill in with a UTF-8 string,
 *                              or NULL to just get the size needed.
 * @param[in] ai_canonname_buf_len The size in bytes of the buffer to fill in
 * @param[in] ai_canonname The native string to copy from
 *
 * @return The size in bytes needed for the output buffer, or 0 on failure
 */
size_t _strcpy_to_utf8(
    char* ai_canonname_buf,
    size_t ai_canonname_buf_len,
    void* ai_canonname)
{
    PWSTR canonname = (PWSTR)ai_canonname;
    int buflen =
        (ai_canonname_buf_len <= INT_MAX) ? (int)ai_canonname_buf_len : INT_MAX;

    size_t buf_needed =
        WideCharToMultiByte(CP_UTF8, 0, canonname, -1, NULL, 0, NULL, NULL);
    if (buf_needed <= buflen)
    {
        WideCharToMultiByte(
            CP_UTF8, 0, canonname, -1, ai_canonname_buf, buflen, NULL, NULL);
    }
    return buf_needed;
}

/* Converts a Windows path to a POSIX style used in enclaves by OE syscalls:
 *
 * <drive_letter>:\<item>\<item> -> /<drive_letter>/<item>/<item>
 * \<item>\<item> -> /<current_drive_letter>/<item>/<item>
 * <item>\<item> -> /<current_drive_letter>/<current_directory>/<item>/<item>
 *
 * This method will also canonicalize away path traversals ('.' & '..') and
 * mixed path separators ('/' & '\') to '/'.
 *
 * This method returns NULL and sets errno on failure.
 * On success, the caller is responsible for calling free() on the
 * returned string.
 *
 * TODO: This method currently does not handle long path names.
 */
char* oe_win_path_to_posix(PCWSTR wpath)
{
    PWSTR wenclave_path = NULL;
    char* enclave_path = NULL;
    size_t enclave_path_length = 0;
    errno_t err = 0;

    if (!wpath || wcsnlen_s(wpath, MAX_PATH) == 0 ||
        wcsnlen_s(wpath, MAX_PATH) == MAX_PATH)
    {
        err = OE_EINVAL;
        goto done;
    }

    enclave_path = _nul_to_dev_null(wpath);
    if (enclave_path)
        goto done;

    uint32_t wenclave_path_length = 0;
    err = _get_full_path_name(wpath, &wenclave_path_length, &wenclave_path);
    if (err)
    {
        goto done;
    }

    // Convert UTF-16LE to UTF-8.
    enclave_path_length = _strcpy_to_utf8(NULL, 0, wenclave_path);
    if (enclave_path_length == 0)
    {
        DWORD winerror = GetLastError();
        err = _winerr_to_errno(winerror);
        OE_TRACE_ERROR("MultiByteToWideChar failed with %#x\n", winerror);
        goto done;
    }
    enclave_path = (char*)malloc(enclave_path_length);
    if (!enclave_path)
    {
        err = OE_ENOMEM;
        goto done;
    }
    _strcpy_to_utf8(enclave_path, enclave_path_length, wenclave_path);

    _canonicalize_path_separators(enclave_path, enclave_path_length, '/');

    _windows_to_oe_syscall_volume_root(enclave_path, enclave_path_length);
    if (enclave_path_length < 2 || enclave_path[0] != '/')
    {
        err = OE_EINVAL;
        free(enclave_path);
        enclave_path = NULL;
        goto done;
    }

done:
    if (wenclave_path)
    {
        free(wenclave_path);
    }
    if (err)
    {
        _set_errno(err);
    }
    return enclave_path;
}

/* Converts a POSIX-style path used in enclaves by OE syscalls to a Windows
 * absolute path:
 *
 * /<drive_letter>/<item>/<item> -> <drive_letter>:\<item>\<item>
 * /<item>/<item> -> <current_drive_letter>:\<item>\<item>
 * <item>/<item> -> <current_drive_letter>:\<current_directory>\<item>\<item>
 *
 * This method will also canonicalize away path traversals ('.' & '..') and
 * mixed path separators ('/' & '\') to '/'.
 *
 * This method returns NULL and sets errno on failure.
 * On success, the caller is responsible for calling free() on the
 * returned string.
 *
 * TODO: This method currently does not handle long path names.
 */
PWSTR oe_syscall_path_to_win(const char* path)
{
    errno_t err = 0;
    PWSTR outpath = NULL;

    if (!path)
    {
        err = OE_EINVAL;
        goto done;
    }

    outpath = _dev_null_to_nul(path);
    if (outpath)
        return outpath;

    bool is_volume_rooted = _is_oe_syscall_path_volume_rooted(path);

    // Convert UTF-8 to UTF-16LE.
    uint32_t wpath_length = MultiByteToWideChar(CP_UTF8, 0, path, -1, NULL, 0);
    if (wpath_length == 0)
    {
        DWORD winerror = GetLastError();
        err = _winerr_to_errno(winerror);
        OE_TRACE_ERROR("MultiByteToWideChar failed with %#x\n", winerror);
        goto done;
    }
    PWSTR wpath = (PWSTR)malloc(wpath_length * sizeof(WCHAR));
    if (!wpath)
    {
        err = OE_ENOMEM;
        goto done;
    }
    MultiByteToWideChar(CP_UTF8, 0, path, -1, wpath, wpath_length);

    uint32_t outpath_length = 0;
    err = _get_full_path_name(wpath, &outpath_length, &outpath);
    free(wpath);
    if (err)
    {
        goto done;
    }

    if (is_volume_rooted)
        _fix_oe_syscall_volume_root(outpath, outpath_length);

done:
    if (err)
    {
        _set_errno(err);
    }
    return outpath;
}

// Windows is much poorer in file bits than POSIX, but it reencoded the
// corresponding bits, so we have to translate.
static unsigned _win_stat_mode_to_posix(unsigned winstat)
{
    unsigned ret_stat = 0;

    if (winstat & _S_IFDIR)
    {
        ret_stat |= OE_S_IFDIR;
    }
    if (winstat & _S_IFCHR)
    {
        ret_stat |= OE_S_IFCHR;
    }
    if (winstat & _S_IFIFO)
    {
        ret_stat |= OE_S_IFIFO;
    }
    if (winstat & _S_IFREG)
    {
        ret_stat |= OE_S_IFREG;
    }
    if (winstat & _S_IREAD)
    {
        ret_stat |= OE_S_IRUSR;
    }
    if (winstat & _S_IWRITE)
    {
        ret_stat |= OE_S_IWUSR;
    }
    if (winstat & _S_IEXEC)
    {
        ret_stat |= OE_S_IXUSR;
    }

    return ret_stat;
}

#define NUM_ACES 4

static HANDLE _createfile(
    PCWSTR fileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile,
    oe_mode_t rwx)
{
    HANDLE ret = INVALID_HANDLE_VALUE;

    PSECURITY_DESCRIPTOR pSD = NULL;
    SECURITY_ATTRIBUTES sa;
    PSID psid[3] = {NULL, NULL, NULL};
    PSID everyonesid = NULL;
    PACL pACL = NULL;
    SID_IDENTIFIER_AUTHORITY SIDAuthWorld = SECURITY_WORLD_SID_AUTHORITY;

    HANDLE hToken;
    TOKEN_PRIMARY_GROUP* GroupInfo;
    TOKEN_OWNER* OwnerInfo;

    oe_mode_t win_modes[] = {GENERIC_EXECUTE, GENERIC_WRITE, GENERIC_READ};
    oe_mode_t current_mode = 01; // bit zero set to 1, which is S_IXOTH
    oe_mode_t grants[] = {0, 0, 0};
    oe_mode_t denies[] = {0, 0, 0};

    for (int i = 2; i >= 0; i--)
    {
        for (int j = 0; j <= 2; j++)
        {
            if (rwx & current_mode)
            {
                grants[i] |= win_modes[j];
            }
            else
            {
                denies[i] |= win_modes[j];
            }
            // Shift the mode bit being examined to the next one in the order X,
            // W, R.
            current_mode <<= 1;
        }
        // Shift the group of mode bits being examined to the next one in the
        // order OTH, GRP, USR And also reset the value of current bit to 1.
    }

    // In this case it needs two deny ACEs, which is impossible.
    // GRP has some permission USR dones not have.
    if ((denies[0] & grants[1]) &&
        // OTH has some permission GRP does not have.
        (denies[1] & grants[2]))
    {
        printf("This mode %04o is not supported on Windows.\n", rwx);
        _set_errno(OE_EINVAL);
        goto done;
    }

    // Deny ACE for Everyone is not necessary since it is the last entry.
    denies[2] = 0;
    // We also need to disable any unnecessary deny for Owner or group.
    // (GRP has some permission USR dones not have) is not true.
    // Deny for USR is unnecessary.
    if (!(denies[0] & grants[1]))
    {
        denies[0] = 0;
    }
    // (OTH has some permission GRP does not have) is not true.
    // Deny for GRP is unneccesarry.
    if (!(denies[1] & grants[2]))
    {
        denies[1] = 0;
    }

    DWORD dwSize = 0, dwRes = 0;
    // Open a handle to the access token for the calling process.
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
    {
        _set_errno(GetLastError());
        goto done;
    }

    // Call GetTokenInformation to get the buffer size.
    if (!GetTokenInformation(hToken, TokenOwner, NULL, 0, &dwSize))
    {
        dwRes = GetLastError();
        if (dwRes != ERROR_INSUFFICIENT_BUFFER)
        {
            _set_errno(GetLastError());
            goto done;
        }
    }

    // Allocate the buffer.
    OwnerInfo = (TOKEN_OWNER*)calloc(dwSize, sizeof(char));

    // Call GetTokenInformation again to get the group information.
    if (!GetTokenInformation(hToken, TokenOwner, OwnerInfo, dwSize, &dwSize))
    {
        _set_errno(GetLastError());
        goto done;
    }

    psid[0] = OwnerInfo->Owner;

    // Call GetTokenInformation to get the buffer size.
    if (!GetTokenInformation(hToken, TokenPrimaryGroup, NULL, 0, &dwSize))
    {
        dwRes = GetLastError();
        if (dwRes != ERROR_INSUFFICIENT_BUFFER)
        {
            _set_errno(GetLastError());
            goto done;
        }
    }

    // Allocate the buffer.
    GroupInfo = (TOKEN_PRIMARY_GROUP*)calloc(dwSize, sizeof(char));

    // Call GetTokenInformation again to get the group information.
    if (!GetTokenInformation(
            hToken, TokenPrimaryGroup, GroupInfo, dwSize, &dwSize))
    {
        _set_errno(GetLastError());
        goto done;
    }

    psid[1] = GroupInfo->PrimaryGroup;

    // Create a SID for the Everyone group.
    if (!AllocateAndInitializeSid(
            &SIDAuthWorld,
            1,
            SECURITY_WORLD_RID,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            &everyonesid))
    {
        _set_errno(GetLastError());
        goto done;
    }

    psid[2] = everyonesid;

    EXPLICIT_ACCESS ea[NUM_ACES];
    ZeroMemory(&ea, NUM_ACES * sizeof(EXPLICIT_ACCESS));

    // Track the number of effective ea, to avoid blank permission ea.
    int num_aces = 0;

    for (int i = 0; i < 3; i++)
    {
        // Set access to each ea. According to ACE canonical rule,
        // deny access must proceed before set access.
        if (i == 1 && denies[i])
        {
            ea[num_aces].grfAccessPermissions = denies[i];
            ea[num_aces].grfAccessMode = DENY_ACCESS;
            ea[num_aces].grfInheritance = NO_INHERITANCE;
            ea[num_aces].Trustee.TrusteeForm = TRUSTEE_IS_SID;
            ea[num_aces].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
            ea[num_aces].Trustee.ptstrName = (LPTSTR)psid[i];

            num_aces++;
        }

        if (grants[i])
        {
            ea[num_aces].grfAccessPermissions = grants[i];
            ea[num_aces].grfAccessMode = SET_ACCESS;
            ea[num_aces].grfInheritance = NO_INHERITANCE;
            ea[num_aces].Trustee.TrusteeForm = TRUSTEE_IS_SID;
            ea[num_aces].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
            ea[num_aces].Trustee.ptstrName = (LPTSTR)psid[i];

            num_aces++;
        }
    }

    // Write the effective ea to DACL.
    if (ERROR_SUCCESS != SetEntriesInAcl(num_aces, ea, NULL, &pACL))
    {
        _set_errno(GetLastError());
        goto done;
    }

    // Deal with directory here.
    // Compared to file, dir has much more aces as for CREATOR OWNER, GROUP
    // It is much easy to let Windows finish the creation then apply the PACL.
    if (dwDesiredAccess == FILE_DIRECTORY_FILE)
    {
        if (!CreateDirectoryW(fileName, NULL))
        {
            _set_errno(_winerr_to_errno(GetLastError()));
            goto done;
        }

        DWORD dwRes = SetNamedSecurityInfoW(
            (PWSTR)fileName,           // name of the object
            SE_FILE_OBJECT,            // type of object
            DACL_SECURITY_INFORMATION, // change only the object's DACL
            NULL,                      // do not change owner
            NULL,                      // do not change group
            pACL,                      // DACL specified
            NULL);                     // do not change SACL

        if (dwRes != ERROR_SUCCESS)
        {
            _set_errno(GetLastError());
            goto done;
        }

        ret = (HANDLE)0;
        goto done;
    }

    // Initialize a security descriptor.
    pSD = (PSECURITY_DESCRIPTOR)calloc(
        SECURITY_DESCRIPTOR_MIN_LENGTH, sizeof(char));
    if (NULL == pSD)
    {
        _set_errno(GetLastError());
        goto done;
    }

    if (!InitializeSecurityDescriptor(pSD, SECURITY_DESCRIPTOR_REVISION))
    {
        _set_errno(GetLastError());
        goto done;
    }

    // Add the ACL to the security descriptor.
    if (!SetSecurityDescriptorDacl(
            pSD,
            TRUE, // bDaclPresent flag
            pACL,
            FALSE)) // not a default DACL
    {
        _set_errno(GetLastError());
        goto done;
    }

    // Initialize a security attributes structure.
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = pSD;
    sa.bInheritHandle = FALSE;

    ret = CreateFileW(
        fileName,
        dwDesiredAccess,
        dwShareMode,
        &sa,
        dwCreationDisposition,
        dwFlagsAndAttributes,
        hTemplateFile);

    // Check GetLastError for CreateFile error code.
    if (ret == INVALID_HANDLE_VALUE)
    {
        _set_errno(GetLastError());
        goto done;
    }

done:
    if (OwnerInfo)
    {
        free(OwnerInfo);
    }
    if (GroupInfo)
    {
        free(GroupInfo);
    }
    if (everyonesid)
    {
        FreeSid(everyonesid);
    }
    if (pACL)
    {
        LocalFree(pACL);
    }
    if (pSD)
    {
        free(pSD);
    }
    return ret;
}

/* Mask to extract open() access mode flags: O_RDONLY, O_WRONLY, O_RDWR. */
#define OPEN_ACCESS_MODE_MASK 0x00000003

oe_host_fd_t oe_syscall_open_ocall(
    const char* pathname,
    int flags,
    oe_mode_t mode)
{
    oe_host_fd_t ret = -1;
    PWSTR wpathname = NULL;

    if (strcmp(pathname, "/dev/stdin") == 0)
    {
        if ((flags & OPEN_ACCESS_MODE_MASK) != OE_O_RDONLY)
        {
            _set_errno(OE_EINVAL);
            goto done;
        }

        ret = (oe_host_fd_t)GetStdHandle(STD_INPUT_HANDLE);
        goto done;
    }
    else if (strcmp(pathname, "/dev/stdout") == 0)
    {
        if ((flags & OPEN_ACCESS_MODE_MASK) != OE_O_WRONLY)
        {
            _set_errno(OE_EINVAL);
            goto done;
        }

        ret = (oe_host_fd_t)GetStdHandle(STD_OUTPUT_HANDLE);
        goto done;
    }
    else if (strcmp(pathname, "/dev/stderr") == 0)
    {
        if ((flags & OPEN_ACCESS_MODE_MASK) != OE_O_WRONLY)
        {
            _set_errno(OE_EINVAL);
            goto done;
        }

        ret = (oe_host_fd_t)GetStdHandle(STD_ERROR_HANDLE);
        goto done;
    }

    DWORD desired_access = 0;
    DWORD share_mode = 0;
    DWORD create_dispos = OPEN_EXISTING;
    DWORD file_flags = (FILE_ATTRIBUTE_NORMAL | FILE_FLAG_POSIX_SEMANTICS);
    wpathname = oe_syscall_path_to_win(pathname);
    if (!wpathname)
    {
        goto done;
    }

    if ((flags & OE_O_DIRECTORY) != 0)
    {
        file_flags |= FILE_FLAG_BACKUP_SEMANTICS; // This will make a directory.
                                                  // Not obvious but there it is
    }

    switch (flags & (OE_O_CREAT | OE_O_EXCL | OE_O_TRUNC))
    {
        case OE_O_CREAT:
        {
            // Create a new file or open an existing file.
            create_dispos = OPEN_ALWAYS;
            break;
        }
        case OE_O_CREAT | OE_O_EXCL:
        case OE_O_CREAT | OE_O_EXCL | OE_O_TRUNC:
        {
            // Create a new file, but fail if it already exists.
            // Ignore `O_TRUNC` with `O_CREAT | O_EXCL`
            create_dispos = CREATE_NEW;
            break;
        }
        case OE_O_CREAT | OE_O_TRUNC:
        {
            // Truncate file if it already exists.
            create_dispos = CREATE_ALWAYS;
            break;
        }
        case OE_O_TRUNC:
        case OE_O_TRUNC | OE_O_EXCL:
        {
            // Truncate file if it exists, otherwise fail. Ignore O_EXCL
            // flag.
            create_dispos = TRUNCATE_EXISTING;
            break;
        }
        case OE_O_EXCL:
        default:
        {
            // Open file if it exists, otherwise fail. Ignore O_EXCL flag.
            create_dispos = OPEN_EXISTING;
            break;
        }
    }

    // In POSIX, we can always share files for read and write unless
    // they have been opened exclusive
    share_mode = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    const int ACCESS_FLAGS = 0x3; // Covers rdonly, wronly rdwr
    switch (flags & ACCESS_FLAGS)
    {
        case OE_O_RDONLY:
        {
            desired_access = GENERIC_READ;
            break;
        }
        case OE_O_WRONLY:
        {
            desired_access =
                (flags & OE_O_APPEND) ? FILE_APPEND_DATA : GENERIC_WRITE;
            break;
        }
        case OE_O_RDWR:
        {
            desired_access =
                GENERIC_READ |
                ((flags & OE_O_APPEND) ? FILE_APPEND_DATA : GENERIC_WRITE);
            break;
        }
        default:
            ret = -1;
            _set_errno(OE_EINVAL);
            goto done;
            break;
    }

    if (mode & OE_S_IRUSR)
        desired_access |= GENERIC_READ;
    if (mode & OE_S_IWUSR)
        desired_access |= GENERIC_WRITE;

    HANDLE h = _createfile(
        wpathname,
        desired_access,
        share_mode,
        create_dispos,
        file_flags,
        NULL,
        mode);
    if (h == INVALID_HANDLE_VALUE)
    {
        _set_errno(_winerr_to_errno(GetLastError()));
        goto done;
    }

    ret = (oe_host_fd_t)h;

done:
    if (wpathname)
    {
        free(wpathname);
    }
    return ret;
}

// Check if handle is a valid file handle.
inline bool _is_valid_file_handle(HANDLE handle)
{
    DWORD file_type = GetFileType(handle);
    // Distinguish between these two cases:
    // 1. a "valid" return of FILE_TYPE_UNKNOWN: the input is valid.
    // 2. a return code due to a calling error: the input is not valid.
    // While GetLastError returns NO_ERROR, it is case 1.
    return (file_type != FILE_TYPE_UNKNOWN || GetLastError() == NO_ERROR);
}

// oe_syscall_read_ocall does not yet support socket.
ssize_t oe_syscall_read_ocall(oe_host_fd_t fd, void* buf, size_t count)
{
    ssize_t ret = -1;
    DWORD bytes_returned = 0;

    HANDLE handle = (HANDLE)fd;

    // Convert fd 0, 1, 2 as needed
    switch (fd)
    {
        case OE_STDIN_FILENO:
            handle = GetStdHandle(STD_INPUT_HANDLE);
            break;

        case OE_STDOUT_FILENO:
        case OE_STDERR_FILENO:
            _set_errno(OE_EBADF);
            goto done;

        default:
            break;
    }

    if (!_is_valid_file_handle(handle))
    {
        _set_errno(OE_EINVAL);
        goto done;
    }

    if (!ReadFile(handle, buf, (DWORD)count, &bytes_returned, NULL))
    {
        _set_errno(_winerr_to_errno(GetLastError()));
        goto done;
    }

    ret = (ssize_t)bytes_returned;

done:
    return ret;
}

// oe_syscall_write_ocall does not yet support socket.
ssize_t oe_syscall_write_ocall(oe_host_fd_t fd, const void* buf, size_t count)
{
    ssize_t ret = -1;
    DWORD bytes_written = 0;

    HANDLE handle = (HANDLE)fd;

    // Convert fd 0, 1, 2 as needed
    switch (fd)
    {
        case OE_STDIN_FILENO:
            // Error. You can't write to stdin
            _set_errno(OE_EBADF);
            goto done;

        case OE_STDOUT_FILENO:
            handle = GetStdHandle(STD_OUTPUT_HANDLE);
            break;

        case OE_STDERR_FILENO:
            handle = GetStdHandle(STD_ERROR_HANDLE);
            break;

        default:
            break;
    }

    if (!_is_valid_file_handle(handle))
    {
        _set_errno(OE_EINVAL);
        goto done;
    }

    if (!WriteFile(handle, buf, (DWORD)count, &bytes_written, NULL))
    {
        _set_errno(_winerr_to_errno(GetLastError()));
        goto done;
    }

    ret = (ssize_t)bytes_written;

done:
    return ret;
}

// oe_syscall_readv_ocall does not yet support socket.
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
        _set_errno(EINVAL);
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

// oe_syscall_writev_ocall does not yet support socket.
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
        _set_errno(EINVAL);
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

// oe_syscall_lseek_ocall does not yet support socket.
oe_off_t oe_syscall_lseek_ocall(oe_host_fd_t fd, oe_off_t offset, int whence)
{
    OE_STATIC_ASSERT(
        SEEK_SET == FILE_BEGIN && SEEK_CUR == FILE_CURRENT &&
        SEEK_END == FILE_END);

    ssize_t ret = -1;

    LARGE_INTEGER const origin_pos = {0};
    LARGE_INTEGER saved_pos;
    if (!SetFilePointerEx(
            (HANDLE)fd, origin_pos, (PLARGE_INTEGER)&saved_pos, FILE_CURRENT))
    {
        _set_errno(_winerr_to_errno(GetLastError()));
        goto done;
    }

    LARGE_INTEGER new_offset = {0};
    new_offset.QuadPart = offset;
    if (!SetFilePointerEx(
            (HANDLE)fd, new_offset, (PLARGE_INTEGER)&new_offset, whence))
    {
        _set_errno(_winerr_to_errno(GetLastError()));
        goto done;
    }

    if (new_offset.QuadPart > LONG_MAX)
    {
        SetFilePointerEx((HANDLE)fd, saved_pos, NULL, FILE_BEGIN);
        _set_errno(EINVAL);
        goto done;
    }

    ret = (oe_off_t)new_offset.QuadPart;

done:
    return ret;
}

ssize_t oe_syscall_pread_ocall(
    oe_host_fd_t fd,
    void* buf,
    size_t count,
    oe_off_t offset)
{
    PANIC;
}

ssize_t oe_syscall_pwrite_ocall(
    oe_host_fd_t fd,
    const void* buf,
    size_t count,
    oe_off_t offset)
{
    PANIC;
}

int oe_syscall_close_ocall(oe_host_fd_t fd)
{
    int ret = -1;
    HANDLE handle = (HANDLE)fd;

    // Convert fd 0, 1, 2 as needed
    switch (fd)
    {
        case OE_STDIN_FILENO:
            handle = GetStdHandle(STD_INPUT_HANDLE);
            break;

        case OE_STDOUT_FILENO:
            handle = GetStdHandle(STD_OUTPUT_HANDLE);
            break;

        case OE_STDERR_FILENO:
            handle = GetStdHandle(STD_ERROR_HANDLE);
            break;

        default:
            break;
    }

    if (handle < 0)
    {
        _set_errno(_winerr_to_errno(GetLastError()));
        goto done;
    }

    ret = !CloseHandle(handle);
    if (ret)
    {
        _set_errno(_winerr_to_errno(GetLastError()));
        goto done;
    }

done:
    return ret;
}

// Unsupported yet.
int oe_syscall_flock_ocall(oe_host_fd_t fd, int operation)
{
    OE_UNUSED(fd);
    OE_UNUSED(operation);
    return 0;
}

int oe_syscall_fsync_ocall(oe_host_fd_t fd)
{
    if (FlushFileBuffers((HANDLE)fd))
        return 0;
    _set_errno(_winerr_to_errno(GetLastError()));
    return -1;
}

int oe_syscall_fdatasync_ocall(oe_host_fd_t fd)
{
    return oe_syscall_fsync_ocall(fd);
}

static oe_host_fd_t _dup_socket(oe_host_fd_t);

oe_host_fd_t oe_syscall_dup_ocall(oe_host_fd_t fd)
{
    oe_host_fd_t ret = -1;
    // suppose fd is a handle.
    HANDLE oldhandle = (HANDLE)fd;

    // If fd is a stdin/out/err, convert it to the corresponding HANDLE.
    switch (fd)
    {
        case OE_STDIN_FILENO:
            oldhandle = GetStdHandle(STD_INPUT_HANDLE);
            break;

        case OE_STDOUT_FILENO:
            oldhandle = GetStdHandle(STD_OUTPUT_HANDLE);
            break;

        case OE_STDERR_FILENO:
            oldhandle = GetStdHandle(STD_ERROR_HANDLE);
            break;

        default:
            break;
    }

    if (_is_valid_file_handle(oldhandle))
    {
        if (DuplicateHandle(
                GetCurrentProcess(),
                oldhandle,
                GetCurrentProcess(),
                (HANDLE*)&ret,
                0,
                FALSE,
                DUPLICATE_SAME_ACCESS))
        {
            _set_errno(0);
        }
        else
        {
            _set_errno(_winerr_to_errno(GetLastError()));
        }
    }
    else
    {
        // The input is a oe_socket_fd_t.
        ret = _dup_socket(fd);
        if (ret == -1)
        {
            _set_errno(OE_EINVAL);
        }
        else
        {
            _set_errno(0);
        }
    }

    return ret;
}

uint64_t oe_syscall_opendir_ocall(const char* pathname)
{
    struct WIN_DIR_DATA* pdir = NULL;

    pdir = (struct WIN_DIR_DATA*)calloc(1, sizeof(struct WIN_DIR_DATA));
    if (!pdir)
    {
        _set_errno(OE_ENOMEM);
        goto done;
    }

    PWSTR wpathname = oe_syscall_path_to_win(pathname);
    if (!wpathname)
    {
        goto done;
    }
    size_t wpathname_length = wcsnlen(wpathname, MAX_PATH);

    /* Allocate enough additional space for '\*' and null-terminator */
    PWSTR dir_search_path =
        (PWSTR)malloc((wpathname_length + 3) * sizeof(WCHAR));
    if (!dir_search_path)
    {
        _set_errno(OE_ENOMEM);
        goto done;
    }

    if (!PathCombineW(dir_search_path, wpathname, L"*"))
    {
        _set_errno(OE_EINVAL);
        goto done;
    }

    pdir->hFind = FindFirstFileW(dir_search_path, &pdir->FindFileData);
    if (pdir->hFind == INVALID_HANDLE_VALUE)
    {
        free(dir_search_path);
        free(pdir);
        pdir = NULL;
        goto done;
    }

    pdir->dir_offs = 0;
    pdir->pdirpath = dir_search_path;

done:
    if (wpathname)
        free(wpathname);

    return (uint64_t)pdir;
}

int oe_syscall_readdir_ocall(uint64_t dirp, struct oe_dirent* entry)
{
    int ret = -1;

    struct WIN_DIR_DATA* pdir = (struct WIN_DIR_DATA*)dirp;
    int nlen = -1;

    _set_errno(0);

    if (!dirp || !entry)
    {
        _set_errno(OE_EINVAL);
        ret = -1;
        goto done;
    }

    // oe_syscall_opendir_ocall already called FindFirstFileW which returned the
    // '.' entry. To preserve the readdir semantics, if oe_syscall_readdir_ocall
    // is passed a valid dirp with the initial offset of 0, we return '.'
    // directly instead of calling FindNextFileA.
    if (pdir->dir_offs == 0)
    {
        entry->d_off = pdir->dir_offs++;
        entry->d_type = OE_DT_DIR;
        entry->d_reclen = sizeof(struct oe_dirent);
        entry->d_name[0] = '.';
        entry->d_name[1] = '\0';
        ret = 0;
        goto done;
    }

    if (!FindNextFileW(pdir->hFind, &pdir->FindFileData))
    {
        DWORD winerr = GetLastError();

        if (winerr == ERROR_NO_MORE_FILES)
        {
            /* Return 1 to indicate there no more entries. */
            ret = 1;
        }
        else
        {
            _set_errno(_winerr_to_errno(winerr));
            ret = -1;
        }
        goto done;
    }

    memset(entry->d_name, 0, OE_NAME_MAX + 1);

    /* Convert from UTF-16LE to UTF-8. */
    if (_strcpy_to_utf8(
            entry->d_name, OE_NAME_MAX + 1, pdir->FindFileData.cFileName) == 0)
    {
        DWORD winerr = GetLastError();
        OE_TRACE_ERROR("_strcpy_to_utf8 failed with %#x\n", winerr);
        _set_errno(_winerr_to_errno(winerr));
        goto done;
    }

    entry->d_type = OE_DT_UNKNOWN;
    if (pdir->FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
    {
        entry->d_type = OE_DT_DIR;
    }
    else if (pdir->FindFileData.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
    {
        entry->d_type = OE_DT_LNK;
    }
    else if (pdir->FindFileData.dwFileAttributes & FILE_ATTRIBUTE_NORMAL)
    {
        entry->d_type = OE_DT_REG;
    }

    entry->d_off = pdir->dir_offs++;
    entry->d_reclen = sizeof(struct oe_dirent);

    ret = 0;

done:
    return ret;
}

void oe_syscall_rewinddir_ocall(uint64_t dirp)
{
    DWORD err = 0;
    struct WIN_DIR_DATA* pdir = (struct WIN_DIR_DATA*)dirp;
    PCWSTR wpathname = pdir->pdirpath;

    if (!FindClose(pdir->hFind))
    {
        _set_errno(_winerr_to_errno(GetLastError()));
        goto done;
    }

    memset(&pdir->FindFileData, 0, (size_t)sizeof(pdir->FindFileData));

    pdir->hFind = FindFirstFileW(wpathname, &pdir->FindFileData);
    if (pdir->hFind == INVALID_HANDLE_VALUE)
    {
        _set_errno(_winerr_to_errno(GetLastError()));
        goto done;
    }
    pdir->dir_offs = 0;

done:
    return;
}

int oe_syscall_closedir_ocall(uint64_t dirp)
{
    int ret = -1;
    struct WIN_DIR_DATA* pdir = (struct WIN_DIR_DATA*)dirp;

    if (!dirp)
    {
        goto done;
    }
    if (!FindClose(pdir->hFind))
    {
        _set_errno(_winerr_to_errno(GetLastError()));
        goto done;
    }

    free((void*)pdir->pdirpath);
    pdir->pdirpath = NULL;
    free(pdir);
    ret = 0;

done:
    return ret;
}

int oe_syscall_stat_ocall(const char* pathname, struct oe_stat_t* buf)
{
    int ret = -1;
    PWSTR wpathname = oe_syscall_path_to_win(pathname);
    if (!wpathname)
    {
        goto done;
    }
    struct _stat64 winstat = {0};

    ret = _wstat64(wpathname, &winstat);
    if (ret < 0)
    {
        _set_errno(_winerr_to_errno(GetLastError()));
        goto done;
    }

    // The macro #define st_atime st_atim.tv_sec
    // provides backward compatibility for older version POSIX. Here we need
    // to undef to avoid winstat.st_atime be treated as winstat.st_atim.tv_sec.
#undef st_atime
#undef st_mtime
#undef st_ctime

    buf->st_dev = winstat.st_dev;
    buf->st_ino = winstat.st_ino;
    buf->st_mode = _win_stat_mode_to_posix(winstat.st_mode);
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

int oe_syscall_access_ocall(const char* pathname, int mode)
{
    int ret = -1;
    PWSTR wpathname = oe_syscall_path_to_win(pathname);
    if (!wpathname)
    {
        goto done;
    }

    HANDLE hToken = NULL;
    TOKEN_OWNER* OwnerInfo = NULL;
    TRUSTEE trustee;
    ACL* pACL = NULL;
    SECURITY_DESCRIPTOR* pSD = NULL;
    DWORD dwSize = 0, dwRes = 0;

    // Open a handle to the access token for the calling process.
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
    {
        _set_errno(GetLastError());
        goto done;
    }

    // Call GetTokenInformation to get the buffer size.
    if (!GetTokenInformation(hToken, TokenOwner, NULL, 0, &dwSize))
    {
        dwRes = GetLastError();
        if (dwRes != ERROR_INSUFFICIENT_BUFFER)
        {
            _set_errno(GetLastError());
            goto done;
        }
    }

    // Allocate the buffer.
    OwnerInfo = (TOKEN_OWNER*)calloc(dwSize, sizeof(char));

    // Call GetTokenInformation again to get the group information.
    if (!GetTokenInformation(hToken, TokenOwner, OwnerInfo, dwSize, &dwSize))
    {
        _set_errno(GetLastError());
        goto done;
    }

    BuildTrusteeWithSid(&trustee, OwnerInfo->Owner);

    // Obtain the file ACL
    dwSize = 0;
    if (!GetFileSecurityW(
            wpathname, DACL_SECURITY_INFORMATION, NULL, 0, &dwSize))
    {
        _set_errno(GetLastError());
        goto done;
    }

    pSD = (SECURITY_DESCRIPTOR*)calloc(dwSize, sizeof(char));
    if (!pSD)
    {
        _set_errno(GetLastError());
        goto done;
    }
    DWORD nSD = dwSize;
    if (!GetFileSecurityW(
            wpathname, DACL_SECURITY_INFORMATION, pSD, nSD, &dwSize))
    {
        _set_errno(GetLastError());
        goto done;
    }

    BOOL bDaclPresent, bDefaulted;
    GetSecurityDescriptorDacl(pSD, &bDaclPresent, &pACL, &bDefaulted);

    // Obtain ACCESS_MASK from TRUSTEE and ACL
    ACCESS_MASK accessMask;
    GetEffectiveRightsFromAcl(pACL, &trustee, &accessMask);

    if ((mode & OE_R_OR) &&
        ((accessMask & STANDARD_RIGHTS_READ) != STANDARD_RIGHTS_READ))
    {
        goto done;
    }
    if ((mode & OE_W_OR) &&
        ((accessMask & STANDARD_RIGHTS_WRITE) != STANDARD_RIGHTS_WRITE))
    {
        goto done;
    }
    if ((mode & OE_X_OR) &&
        ((accessMask & STANDARD_RIGHTS_EXECUTE) != STANDARD_RIGHTS_EXECUTE))
    {
        goto done;
    }

    ret = 0;

done:
    if (wpathname)
    {
        free(wpathname);
    }
    if (pACL)
    {
        LocalFree(pACL);
    }
    if (pSD)
    {
        free(pSD);
    }
    if (OwnerInfo)
    {
        free(OwnerInfo);
    }
    return ret;
}

int oe_syscall_link_ocall(const char* oldpath, const char* newpath)
{
    int ret = -1;
    PWSTR oldwpath = oe_syscall_path_to_win(oldpath);
    PWSTR newwpath = oe_syscall_path_to_win(newpath);
    if (!oldwpath || !newwpath)
    {
        goto done;
    }

    if (!CreateHardLinkW(newwpath, oldwpath, NULL))
    {
        _set_errno(_winerr_to_errno(GetLastError()));
        goto done;
    }
    ret = 0;

done:
    if (oldwpath)
    {
        free(oldwpath);
    }

    if (newwpath)
    {
        free(newwpath);
    }
    return ret;
}

int oe_syscall_unlink_ocall(const char* pathname)
{
    int ret = -1;
    PWSTR wpathname = oe_syscall_path_to_win(pathname);
    if (!wpathname)
    {
        goto done;
    }

    if (!DeleteFileW(wpathname))
    {
        _set_errno(_winerr_to_errno(GetLastError()));
        goto done;
    }

    ret = 0;

done:
    if (wpathname)
    {
        free(wpathname);
    }
    return ret;
}

int oe_syscall_rename_ocall(const char* oldpath, const char* newpath)
{
    int ret = -1;
    PWSTR oldwpath = oe_syscall_path_to_win(oldpath);
    PWSTR newwpath = oe_syscall_path_to_win(newpath);
    if (!oldwpath || !newwpath)
    {
        goto done;
    }

    ret = !MoveFileExW(oldwpath, newwpath, MOVEFILE_COPY_ALLOWED);
    if (ret)
    {
        _set_errno(_winerr_to_errno(GetLastError()));
        goto done;
    }

done:
    if (oldwpath)
    {
        free(oldwpath);
    }
    if (newwpath)
    {
        free(newwpath);
    }
    return ret;
}

int oe_syscall_truncate_ocall(const char* pathname, oe_off_t length)
{
    int ret = -1;
    LARGE_INTEGER new_offset = {0};
    PWSTR wpathname = oe_syscall_path_to_win(pathname);
    if (!wpathname)
    {
        goto done;
    }

    HANDLE h = CreateFileW(
        wpathname,
        GENERIC_WRITE,
        FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (h == INVALID_HANDLE_VALUE)
    {
        _set_errno(_winerr_to_errno(GetLastError()));
        goto done;
    }

    new_offset.QuadPart = length;
    if (!SetFilePointerEx(h, new_offset, NULL, FILE_BEGIN))
    {
        _set_errno(_winerr_to_errno(GetLastError()));
        goto done;
    }

    if (!SetEndOfFile(h))
    {
        _set_errno(_winerr_to_errno(GetLastError()));
        goto done;
    }

    ret = 0;

done:
    if (h != INVALID_HANDLE_VALUE)
    {
        CloseHandle(h);
    }
    if (wpathname)
    {
        free(wpathname);
    }
    return ret;
}

int oe_syscall_mkdir_ocall(const char* pathname, oe_mode_t mode)
{
    int ret = -1;
    PWSTR wpathname = oe_syscall_path_to_win(pathname);
    if (!wpathname)
    {
        goto done;
    }

    HANDLE h = _createfile(wpathname, FILE_DIRECTORY_FILE, 0, 0, 0, NULL, mode);
    if (h == INVALID_HANDLE_VALUE)
    {
        _set_errno(_winerr_to_errno(GetLastError()));
        goto done;
    }

    ret = 0;

done:
    if (wpathname)
    {
        free(wpathname);
    }
    return ret;
}

int oe_syscall_rmdir_ocall(const char* pathname)
{
    int ret = -1;
    PWSTR wpathname = oe_syscall_path_to_win(pathname);
    if (!wpathname)
    {
        goto done;
    }

    if (!RemoveDirectoryW(wpathname))
    {
        _set_errno(_winerr_to_errno(GetLastError()));
        goto done;
    }

    ret = 0;

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

    ret = send(_get_socket(sockfd), buf, (int)len, flags);
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
        (int)len,
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
    if (fd < 0)
    {
        _set_errno(OE_EINVAL);
        return -1;
    }

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
    int ret;

    errno = 0;

    ret = getsockname(_get_socket(sockfd), (struct sockaddr*)addr, &addrlen_in);

    if (ret != 0)
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

int oe_syscall_getpeername_ocall(
    oe_host_fd_t sockfd,
    struct oe_sockaddr* addr,
    oe_socklen_t addrlen_in,
    oe_socklen_t* addrlen_out)
{
    int ret;

    errno = 0;

    ret = getpeername(_get_socket(sockfd), (struct sockaddr*)addr, &addrlen_in);

    if (ret != 0)
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

    // Convert the node name (if any) from UTF-8 to UTF-16LE.
    PWSTR wnode = NULL;
    WCHAR wnode_buf[NI_MAXHOST];
    if (node != NULL)
    {
        if (MultiByteToWideChar(CP_UTF8, 0, node, -1, wnode_buf, NI_MAXHOST) ==
            0)
        {
            ret = OE_EAI_FAIL;
            goto done;
        }
        wnode = wnode_buf;
    }

    // Convert the service name (if any) from UTF-8 to UTF-16LE.
    PWSTR wservice = NULL;
    WCHAR wserv_buf[NI_MAXSERV];
    if (service != NULL)
    {
        if (MultiByteToWideChar(
                CP_UTF8, 0, service, -1, wserv_buf, NI_MAXSERV) == 0)
        {
            ret = OE_EAI_FAIL;
            goto done;
        }
        wservice = wserv_buf;
    }

    // The addrinfo structure is the same between ADDRINFOA and ADDRINFOW
    // except for the types of pointers.  However, in the hints, the pointer
    // fields must always be NULL anyway, so we don't need any conversion
    // other than a simple cast.
    ADDRINFOW* whints = (ADDRINFOW*)hints;

    // Get the list of ADDRINFOW structs. Again a simple cast will do
    // since we will deal with the type of pointer when reading the values
    // out of the struct.
    ret = GetAddrInfoW(wnode, wservice, whints, (ADDRINFOW**)&handle->res);
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
    WCHAR whost[NI_MAXHOST];
    WCHAR wserv[NI_MAXSERV];
    errno = 0;

    // Get the name in UTF-16LE format. We cannot use getnameinfo since it uses
    // ANSI code pages and the current code page may not be able to represent
    // the name.
    int ret = GetNameInfoW(
        (const struct sockaddr*)sa,
        salen,
        whost,
        _countof(whost),
        wserv,
        _countof(wserv),
        flags);
    if (ret != 0)
        return _wsaerr_to_eai(ret);

    // Convert UTF-16LE to UTF-8.
    if ((hostlen > 0) && (_strcpy_to_utf8(host, hostlen, whost) == 0))
    {
        return EAI_FAIL;
    }
    if ((servlen > 0) && (_strcpy_to_utf8(serv, servlen, wserv) == 0))
    {
        return EAI_FAIL;
    }

    return 0;
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
        sprintf_s(buf->sysname, 65, "WindowsServer");
        sprintf_s(buf->version, 65, "2016OrAbove");
    }
    else if (IsWindows10OrGreater())
    {
        sprintf_s(buf->sysname, 65, "Windows10OrGreater");
        sprintf_s(buf->version, 65, "10OrAbove");
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
