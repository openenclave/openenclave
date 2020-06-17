// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_HOST_SOCKET_H
#define _OE_HOST_SOCKET_H

#include <openenclave/corelibc/bits/types.h>
#include <openenclave/corelibc/errno.h>
#include <openenclave/internal/syscall/sys/socket.h>
#include <openenclave/internal/syscall/types.h>
#include <stdint.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <sys/socket.h>
#endif

OE_EXTERNC_BEGIN

#define GETADDRINFO_HANDLE_MAGIC 0xed11d13a

typedef struct _getaddrinfo_handle
{
    uint64_t magic;
    struct addrinfo* res;
    struct addrinfo* next;
} getaddrinfo_handle_t;

OE_INLINE getaddrinfo_handle_t* _cast_getaddrinfo_handle(void* handle_);

/**
 * _strcpy_to_utf8.
 *
 * This function copies a native (UTF-16LE on Windows) string into a UTF-8
 * buffer. If the buffer is not large enough, the value returned will be larger
 * than ai_canonname_buf_len.
 *
 * @param[out] ai_canonname_buf The buffer to fill in with a UTF-8 string
 * @param[in] ai_canonname_buf_len The size in bytes of the buffer to fill in
 * @param[in] ai_canonname The native string to copy from
 *
 * @return The size in bytes needed for the output buffer, or 0 on failure
 */
size_t _strcpy_to_utf8(
    char* ai_canonname_buf,
    size_t ai_canonname_buf_len,
    void* ai_canonname);

int _getaddrinfo_read(
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
    char* ai_canonname,
    int* err_no);

OE_INLINE getaddrinfo_handle_t* _cast_getaddrinfo_handle(void* handle_)
{
    getaddrinfo_handle_t* handle = (getaddrinfo_handle_t*)handle_;

    if (!handle || handle->magic != GETADDRINFO_HANDLE_MAGIC || !handle->res)
        return NULL;

    return handle;
}

int _getaddrinfo_read(
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
    char* ai_canonname,
    int* err_no)
{
    int ret = -1;
    getaddrinfo_handle_t* handle = _cast_getaddrinfo_handle((void*)handle_);

    if (!err_no)
    {
        goto done;
    }

    if (!handle || !ai_flags || !ai_family || !ai_socktype || !ai_protocol ||
        !ai_addrlen || !ai_canonnamelen)
    {
        *err_no = OE_EINVAL;

        goto done;
    }

    if (!ai_addr && ai_addrlen_in)
    {
        *err_no = OE_EINVAL;
        goto done;
    }

    if (!ai_canonname && ai_canonnamelen_in)
    {
        *err_no = OE_EINVAL;
        goto done;
    }

    if (handle->next)
    {
        struct addrinfo* p = handle->next;

        *ai_flags = p->ai_flags;
        *ai_family = p->ai_family;
        *ai_socktype = p->ai_socktype;
        *ai_protocol = p->ai_protocol;
        *ai_addrlen = (oe_socklen_t)p->ai_addrlen;
        *ai_canonnamelen = 0;

        if (*ai_addrlen > ai_addrlen_in)
        {
            *err_no = OE_ENAMETOOLONG;
            goto done;
        }

        if (ai_addr)
        {
            memcpy(ai_addr, p->ai_addr, *ai_addrlen);
        }

        if (ai_canonname && p->ai_canonname)
        {
            *ai_canonnamelen = _strcpy_to_utf8(
                ai_canonname, ai_canonnamelen_in, p->ai_canonname);
            if (*ai_canonnamelen > ai_canonnamelen_in)
            {
                *err_no = OE_ENAMETOOLONG;
                goto done;
            }
        }

        handle->next = handle->next->ai_next;

        ret = 0;
        goto done;
    }
    else
    {
        /* Done */
        ret = 1;
        goto done;
    }

done:
    return ret;
}

OE_EXTERNC_END

#endif // _OE_HOST_SOCKET_H
