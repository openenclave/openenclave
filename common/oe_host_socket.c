// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "oe_host_socket.h"
#include <stdlib.h>

// Winsock and Linux POSIX socket APIs are nearly identical. The only difference
// is the error handling. Simply define the necessary error macros and codes.
// And the implementation can be shared.
#ifdef _WIN32
#define SOCKET_ERRNO() WSAGetLastError()
#define SET_SOCKET_ERRNO(_err) WSASetLastError(_err)

#undef EINVAL
#define EINVAL WSAEINVAL

#else

#define SOCKET_ERRNO() errno
#define SET_SOCKET_ERRNO(_err) \
    do                         \
    {                          \
        errno = _err           \
    } while (0)

#endif

static getaddrinfo_handle_t* _getaddrinfo_handle(void* handle_)
{
    getaddrinfo_handle_t* handle = (getaddrinfo_handle_t*)handle_;

    if (!handle || handle->magic != GETADDRINFO_HANDLE_MAGIC || !handle->res)
        return NULL;

    return handle;
}

int _getaddrinfo_open_ocall(
    const char* node,
    const char* service,
    const struct oe_addrinfo* hints,
    uint64_t* handle_out)
{
    int ret = EAI_FAIL;
    getaddrinfo_handle_t* handle = NULL;

    SET_SOCKET_ERRNO(0);

    if (handle_out)
        *handle_out = 0;

    if (!handle_out)
    {
        ret = EAI_SYSTEM;
        SET_SOCKET_ERRNO(EINVAL);
        goto done;
    }

    if (!(handle = calloc(1, sizeof(getaddrinfo_handle_t))))
    {
        ret = EAI_MEMORY;
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

done:

    if (handle)
        free(handle);

    return ret;
}

int _getaddrinfo_read_ocall(
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
    int ret = -1;
    getaddrinfo_handle_t* handle = _cast_getaddrinfo_handle((void*)handle_);

    SET_SOCKET_ERRNO(0);

    if (!handle || !ai_flags || !ai_family || !ai_socktype || !ai_protocol ||
        !ai_addrlen || !ai_canonnamelen)
    {
        SET_SOCKET_ERRNO(EINVAL);
        goto done;
    }

    if (!ai_addr && ai_addrlen_in)
    {
        SET_SOCKET_ERRNO(EINVAL);
        goto done;
    }

    if (!ai_canonname && ai_canonnamelen_in)
    {
        SET_SOCKET_ERRNO(EINVAL);
        goto done;
    }

    if (handle->next)
    {
        struct addrinfo* p = handle->next;

        *ai_flags = p->ai_flags;
        *ai_family = p->ai_family;
        *ai_socktype = p->ai_socktype;
        *ai_protocol = p->ai_protocol;
        *ai_addrlen = p->ai_addrlen;

        if (p->ai_canonname)
            *ai_canonnamelen = strlen(p->ai_canonname) + 1;
        else
            *ai_canonnamelen = 0;

        if (*ai_addrlen > ai_addrlen_in)
        {
            errno = ENAMETOOLONG;
            goto done;
        }

        if (*ai_canonnamelen > ai_canonnamelen_in)
        {
            errno = ENAMETOOLONG;
            goto done;
        }

        memcpy(ai_addr, p->ai_addr, *ai_addrlen);

        if (p->ai_canonname)
            memcpy(ai_canonname, p->ai_canonname, *ai_canonnamelen);

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

int _getaddrinfo_close_ocall(uint64_t handle_)
{
    int ret = -1;
    getaddrinfo_handle_t* handle = _cast_getaddrinfo_handle((void*)handle_);

    SET_SOCKET_ERRNO(0);

    if (!handle)
    {
        SET_SOCKET_ERRNO(EINVAL);
        goto done;
    }

    freeaddrinfo(handle->res);
    free(handle);

    ret = 0;

done:
    return ret;
}
