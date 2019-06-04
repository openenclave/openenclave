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

#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <direct.h>
#include <io.h>
#include <stdint.h>
#include <sys/stat.h>

// clang-format off
#include <windows.h>
// clang-format on

#include "posix_u.h"

#include "openenclave/corelibc/errno.h"
#include "openenclave/corelibc/fcntl.h"
#include "openenclave/corelibc/sys/epoll.h"
#include "openenclave/corelibc/dirent.h"
#include "../hostthread.h"
#include <assert.h>

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

/*
**==============================================================================
**
** Path conversion:
**
**==============================================================================
*/

// Allocates char* string which follows the expected rules for
// enclaves. Paths in the format
// <driveletter>:\<item>\<item> -> /<driveletter>/<item>/item>
// <driveletter>:/<item>/<item> -> /<driveletter>/<item>/item>
// paths without drive letter are detected and the drive added
// /<item>/<item> -> /<current driveletter>/<item>/item>
// relative paths are translated to absolute with drive letter
// returns null if the string is illegal
//
// The string  must be freed
// ATTN: we don't handle paths which start with the "\\?\" thing. don't really
// think we need them
//
char* oe_win_path_to_posix(const char* path)
{
    size_t required_size = 0;
    size_t current_dir_len = 0;
    char* current_dir = NULL;
    char* enclave_path = NULL;

    if (!path)
    {
        return NULL;
    }
    // Relative or incomplete path?

    // absolute path with drive letter.
    // we do not handle device type paths ("CON:) or double-letter paths in case
    // of really large numbers of disks (>26). If you have those, mount on
    // windows
    //
    if (isalpha(path[0]) && path[1] == ':')
    {
        // Abosolute path is drive letter
        required_size = strlen(path) + 1;
    }
    else if (path[0] == '/' || path[0] == '\\')
    {
        required_size = strlen(path) + 3; // Add a drive letter to the path
    }
    else
    {
        current_dir = _getcwd(NULL, 32767);
        current_dir_len = strlen(current_dir);

        if (isalpha(*current_dir) && (current_dir[1] == ':'))
        {
            // This is expected. We convert drive: to /drive.

            char drive_letter = *current_dir;
            *current_dir = '/';
            current_dir[1] = drive_letter;
        }
        // relative path. If the path starts with "." or ".." we accomodate
        required_size = strlen(path) + current_dir_len + 1;
    }

    enclave_path = (char*)calloc(1, required_size);

    const char* psrc = path;
    const char* plimit = path + strlen(path);
    char* pdst = enclave_path;

    if (isalpha(*psrc) && psrc[1] == ':')
    {
        *pdst++ = '/';
        *pdst++ = *psrc;
        psrc += 2;
    }
    else if (*psrc == '/')
    {
        *pdst++ = '/';
        *pdst++ = _getdrive() + 'a';
    }
    else if (*psrc == '.')
    {
        memcpy(pdst, current_dir, current_dir_len);
        if (psrc[1] == '/' || psrc[1] == '\\')
        {
            pdst += current_dir_len;
            psrc++;
        }
        else if (psrc[1] == '.' && (psrc[2] == '/' || psrc[2] == '\\'))
        {
            char* rstr = strrchr(
                current_dir, '\\'); // getcwd always returns at least '\'
            pdst += current_dir_len - (rstr - current_dir);
            // When we shortend the curdir by 1 slash, we perform the ".."
            // operation we could leave it in here, but at least sometimes this
            // will allow a path that would otherwise be too long
            psrc += 2;
        }
        else
        {
            // It is an incomplete which starts with a file which starts with .
            // so we dont increment psrc at all
            pdst += current_dir_len;
            *pdst = '/';
        }
    }
    else
    {
        // Still a relative path
        memcpy(pdst, current_dir, current_dir_len);
        pdst += current_dir_len;
        *pdst++ = '/';
    }

    // Since we have to translater slashes, use a loop rather than memcpy
    while (psrc < plimit)
    {
        if (*psrc == '\\')
        {
            *pdst = '/';
        }
        else
        {
            *pdst = *psrc;
        }
        psrc++;
        pdst++;
    }
    *pdst = '\0';

    if (current_dir)
    {
        free(current_dir);
    }
    return enclave_path;
}

// Allocates WCHAR* string which follows the expected rules for
// enclaves comminication with the host file system API. Paths in the format
// /<driveletter>/<item>/<item>  become <driveletter>:/<item>/<item>
//
// The resulting string, especially with a relative path, will probably contain
// mixed slashes. We beleive Windows handles this.
//
// Adds the string "post" to the resulting string end
//
// The string  must be freed
WCHAR* oe_posix_path_to_win(const char* path, const char* post)
{
    size_t required_size = 0;
    size_t current_dir_len = 0;
    char* current_dir = NULL;
    int pathlen = MultiByteToWideChar(CP_UTF8, 0, path, -1, NULL, 0);
    size_t postlen = MultiByteToWideChar(CP_UTF8, 0, post, -1, NULL, 0);
    if (post)
    {
        postlen = MultiByteToWideChar(CP_UTF8, 0, post, -1, NULL, 0);
    }

    WCHAR* wpath = NULL;

    if (path[0] == '/')
    {
        if (isalpha(path[1]) && path[2] == '/')
        {
            wpath =
                (WCHAR*)(calloc((pathlen + postlen + 1) * sizeof(WCHAR), 1));
            MultiByteToWideChar(CP_UTF8, 0, path, -1, wpath, (int)pathlen);
            if (postlen)
            {
                MultiByteToWideChar(
                    CP_UTF8, 0, post, -1, wpath + pathlen - 1, (int)postlen);
            }
            WCHAR drive_letter = wpath[1];
            wpath[0] = drive_letter;
            wpath[1] = ':';
        }
        else
        {
            // Absolute path needs drive letter
            wpath =
                (WCHAR*)(calloc((pathlen + postlen + 3) * sizeof(WCHAR), 1));
            MultiByteToWideChar(CP_UTF8, 0, path, -1, wpath + 2, (int)pathlen);
            if (postlen)
            {
                MultiByteToWideChar(
                    CP_UTF8, 0, post, -1, wpath + pathlen - 1, (int)postlen);
            }
            WCHAR drive_letter = _getdrive() + 'A';
            wpath[0] = drive_letter;
            wpath[1] = ':';
        }
    }
    else
    {
        // Relative path
        WCHAR* current_dir = _wgetcwd(NULL, 32767);
        if (!current_dir)
        {
            _set_errno(OE_ENOMEM);
            return NULL;
        }
        size_t current_dir_len = wcslen(current_dir);

        wpath = (WCHAR*)(calloc(
            (pathlen + current_dir_len + postlen + 1) * sizeof(WCHAR), 1));
        memcpy(wpath, current_dir, current_dir_len);
        wpath[current_dir_len] = '/';
        MultiByteToWideChar(
            CP_UTF8, 0, path, -1, wpath + current_dir_len, pathlen);
        if (postlen)
        {
            MultiByteToWideChar(
                CP_UTF8,
                0,
                path,
                -1,
                wpath + current_dir_len + pathlen - 1,
                (int)postlen);
        }

        free(current_dir);
    }
    return wpath;
}

/*
**==============================================================================
**
** Local definitions.
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
            _set_errno(OE_EINVAL);
            goto done;
        }

        if (!DuplicateHandle(
                GetCurrentProcess(),
                GetStdHandle(STD_INPUT_HANDLE),
                GetCurrentProcess(),
                (HANDLE*)&ret,
                0,
                FALSE,
                DUPLICATE_SAME_ACCESS))
        {
            _set_errno(_winerr_to_errno(GetLastError()));
            goto done;
        }
    }
    else if (strcmp(pathname, "/dev/stdout") == 0)
    {
        if ((flags & 0x00000003) != OE_O_WRONLY)
        {
            _set_errno(OE_EINVAL);
            goto done;
        }

        if (!DuplicateHandle(
                GetCurrentProcess(),
                GetStdHandle(STD_OUTPUT_HANDLE),
                GetCurrentProcess(),
                (HANDLE*)&ret,
                0,
                FALSE,
                DUPLICATE_SAME_ACCESS))
        {
            _set_errno(_winerr_to_errno(GetLastError()));
            goto done;
        }
    }
    else if (strcmp(pathname, "/dev/stderr") == 0)
    {
        if ((flags & 0x00000003) != OE_O_WRONLY)
        {
            _set_errno(OE_EINVAL);
            goto done;
        }

        if (!DuplicateHandle(
                GetCurrentProcess(),
                GetStdHandle(STD_ERROR_HANDLE),
                GetCurrentProcess(),
                (HANDLE*)&ret,
                0,
                FALSE,
                DUPLICATE_SAME_ACCESS))
        {
            _set_errno(_winerr_to_errno(GetLastError()));
            goto done;
        }
    }
    else
    {
        DWORD desired_access = 0;
        DWORD share_mode = 0;
        DWORD create_dispos = OPEN_EXISTING;
        DWORD file_flags = (FILE_ATTRIBUTE_NORMAL | FILE_FLAG_POSIX_SEMANTICS);
        WCHAR* wpathname = oe_posix_path_to_win(pathname, NULL);

        if ((flags & OE_O_DIRECTORY) != 0)
        {
            file_flags |=
                FILE_FLAG_BACKUP_SEMANTICS; // This will make a directory. Not
                                            // obvious but there it is
        }

        /* Open flags are neither a bitmask nor a sequence, so switching or
         * masking don't really work. */

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

        // in linux land, we can always share files for read and write unless
        // they have been opened exclusive
        share_mode = FILE_SHARE_READ | FILE_SHARE_WRITE;
        const int ACCESS_FLAGS = 0x3; // Covers rdonly, wronly rdwr
        switch (flags & ACCESS_FLAGS)
        {
            case OE_O_RDONLY: // 0
                desired_access |= GENERIC_READ;
                if (flags & OE_O_EXCL)
                {
                    share_mode = FILE_SHARE_WRITE;
                }
                break;

            case OE_O_WRONLY: // 1
                desired_access |= GENERIC_WRITE;
                if (flags & OE_O_EXCL)
                {
                    share_mode = FILE_SHARE_READ;
                }
                break;

            case OE_O_RDWR: // 2 or 3
                desired_access |= GENERIC_READ | GENERIC_WRITE;
                if (flags & OE_O_EXCL)
                {
                    share_mode = 0;
                }
                break;

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
            _set_errno(_winerr_to_errno(GetLastError()));
            goto done;
        }

        ret = (oe_host_fd_t)h;

        if (wpathname)
            free(wpathname);
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
            _set_errno(OE_EBADF);
            goto done;

        case 2:
            _set_errno(OE_EBADF);
            goto done;

        default:
            break;
    }

    if (!ReadFile((HANDLE)fd, buf, (DWORD)count, &bytes_returned, NULL))
    {
        _set_errno(_winerr_to_errno(GetLastError()));
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
            _set_errno(OE_EBADF);
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
        _set_errno(_winerr_to_errno(GetLastError()));
        goto done;
    }

    ret = (ssize_t)bytes_written;

done:
    return ret;
}

ssize_t oe_posix_readv_ocall(
    oe_host_fd_t fd,
    void* iov_buf,
    int iovcnt,
    size_t iov_buf_size)
{
    struct oe_iovec* iov = (struct oe_iovec*)iov_buf;
    ssize_t ret = -1;
    ssize_t size_read;

    OE_UNUSED(iov_buf_size);

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

        size_read = oe_posix_read_ocall(fd, buf, count);
    }

    ret = size_read;

done:
    return ret;
}

ssize_t oe_posix_writev_ocall(
    oe_host_fd_t fd,
    const void* iov_buf,
    int iovcnt,
    size_t iov_buf_size)
{
    ssize_t ret = -1;
    ssize_t size_written;
    struct oe_iovec* iov = (struct oe_iovec*)iov_buf;

    OE_UNUSED(iov_buf_size);

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

        size_written = oe_posix_write_ocall(fd, buf, count);
    }

    ret = size_written;

done:
    return ret;
}

oe_off_t oe_posix_lseek_ocall(oe_host_fd_t fd, oe_off_t offset, int whence)
{
    PANIC;
}

int oe_posix_close_ocall(oe_host_fd_t fd)
{
    // Convert fd 0, 1, 2 as needed
    switch (fd)
    {
        case 0:
            fd = (oe_host_fd_t)GetStdHandle(STD_INPUT_HANDLE);
            break;

        case 1:
            fd = (oe_host_fd_t)GetStdHandle(STD_OUTPUT_HANDLE);
            break;

        case 2:
            fd = (oe_host_fd_t)GetStdHandle(STD_ERROR_HANDLE);
            break;

        default:
            break;
    }

    if (!CloseHandle((HANDLE)fd))
    {
        _set_errno(OE_EINVAL);
        return -1;
    }

    return 0;
}

oe_host_fd_t oe_posix_dup_ocall(oe_host_fd_t oldfd)
{
    PANIC;
}

uint64_t oe_posix_opendir_ocall(const char* pathname)
{
    PANIC;
}

int oe_posix_readdir_ocall(uint64_t dirp, struct oe_dirent* entry)
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
    PANIC;
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

int oe_posix_truncate_ocall(const char* pathname, oe_off_t length)
{
    PANIC;
}

int oe_posix_mkdir_ocall(const char* pathname, oe_mode_t mode)
{
    PANIC;
}

int oe_posix_rmdir_ocall(const char* pathname)
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

oe_host_fd_t oe_posix_socket_ocall(int domain, int type, int protocol)
{
    PANIC;
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
    PANIC;
}

oe_host_fd_t oe_posix_accept_ocall(
    oe_host_fd_t sockfd,
    struct oe_sockaddr* addr,
    oe_socklen_t addrlen_in,
    oe_socklen_t* addrlen_out)
{
    PANIC;
}

int oe_posix_bind_ocall(
    oe_host_fd_t sockfd,
    const struct oe_sockaddr* addr,
    oe_socklen_t addrlen)
{
    PANIC;
}

int oe_posix_listen_ocall(oe_host_fd_t sockfd, int backlog)
{
    PANIC;
}

ssize_t oe_posix_recvmsg_ocall(
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

ssize_t oe_posix_sendmsg_ocall(
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

ssize_t oe_posix_recv_ocall(
    oe_host_fd_t sockfd,
    void* buf,
    size_t len,
    int flags)
{
    PANIC;
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
    PANIC;
}

ssize_t oe_posix_sendto_ocall(
    oe_host_fd_t sockfd,
    const void* buf,
    size_t len,
    int flags,
    const struct oe_sockaddr* src_addr,
    oe_socklen_t addrlen)
{
    PANIC;
}

ssize_t oe_posix_recvv_ocall(
    oe_host_fd_t fd,
    void* iov_buf,
    int iovcnt,
    size_t iov_buf_size)
{
    PANIC;
}

ssize_t oe_posix_sendv_ocall(
    oe_host_fd_t fd,
    const void* iov_buf,
    int iovcnt,
    size_t iov_buf_size)
{
    PANIC;
}

int oe_posix_shutdown_ocall(oe_host_fd_t sockfd, int how)
{
    PANIC;
}

int oe_posix_close_socket_ocall(oe_host_fd_t sockfd)
{
    PANIC;
}

int oe_posix_fcntl_ocall(oe_host_fd_t fd, int cmd, uint64_t arg)
{
    PANIC;
}

#define TIOCGWINSZ 0x5413
#define TIOCSWINSZ 0x5414

int oe_posix_ioctl_ocall(oe_host_fd_t fd, uint64_t request, uint64_t arg)
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

int oe_posix_setsockopt_ocall(
    oe_host_fd_t sockfd,
    int level,
    int optname,
    const void* optval,
    oe_socklen_t optlen)
{
    PANIC;
}

int oe_posix_getsockopt_ocall(
    oe_host_fd_t sockfd,
    int level,
    int optname,
    void* optval,
    oe_socklen_t optlen_in,
    oe_socklen_t* optlen_out)
{
    PANIC;
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

int oe_posix_getaddrinfo_open_ocall(
    const char* node,
    const char* service,
    const struct oe_addrinfo* hints,
    uint64_t* handle_out)
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

int oe_posix_epoll_wait_ocall(
    int64_t epfd,
    struct oe_epoll_event* events,
    unsigned int maxevents,
    int timeout)
{
    PANIC;
}

int oe_posix_epoll_wake_ocall(void)
{
    PANIC;
}

int oe_posix_epoll_ctl_ocall(
    int64_t epfd,
    int op,
    int64_t fd,
    struct oe_epoll_event* event)
{
    PANIC;
}

int oe_posix_epoll_close_ocall(oe_host_fd_t epfd)
{
    PANIC;
}

int oe_posix_shutdown_polling_device_ocall(oe_host_fd_t fd)
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

int oe_posix_poll_ocall(
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
    PANIC;
}
