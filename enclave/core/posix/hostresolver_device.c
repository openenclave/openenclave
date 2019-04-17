// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#define _GNU_SOURCE

// clang-format off
#include <openenclave/enclave.h>
// clang-format on

#include <openenclave/internal/device.h>
#include <openenclave/corelibc/sys/socket.h>
#include <openenclave/corelibc/netdb.h>
#include <openenclave/internal/resolver.h>
#include <openenclave/bits/safemath.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/thread.h>
#include <openenclave/internal/print.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/bits/module.h>
#include <openenclave/internal/trace.h>
#include "oe_t.h"

/*
**==============================================================================
**
** hostresolv operations:
**
**==============================================================================
*/

// The host resolver is not actually a device in the file descriptor sense.

#define RESOLV_MAGIC 0x536f636b

typedef struct _resolv
{
    struct _oe_resolver base;
    uint32_t magic;
} resolv_t;

static resolv_t* _cast_resolv(const oe_resolver_t* device)
{
    resolv_t* resolv = (resolv_t*)device;

    if (resolv == NULL || resolv->magic != RESOLV_MAGIC)
    {
        resolv = NULL;
        OE_TRACE_ERROR("resolver is invalid");
        goto done;
    }

done:
    return resolv;
}

static resolv_t _hostresolv;

static ssize_t _hostresolv_getnameinfo(
    oe_resolver_t* dev,
    const struct oe_sockaddr* sa,
    socklen_t salen,
    char* host,
    socklen_t hostlen,
    char* serv,
    socklen_t servlen,
    int flags)
{
    int ret = OE_EAI_FAIL;

    OE_UNUSED(dev);

    oe_errno = 0;

    if (oe_posix_getnameinfo_ocall(
            &ret,
            (const struct sockaddr*)sa,
            salen,
            host,
            hostlen,
            serv,
            servlen,
            flags,
            &oe_errno) != OE_OK)
    {
        goto done;
    }

done:

    return ret;
}

static int _hostresolv_getaddrinfo(
    oe_resolver_t* resolv,
    const char* node,
    const char* service,
    const struct oe_addrinfo* hints,
    struct oe_addrinfo** res)
{
    int ret = OE_EAI_FAIL;
    void* handle = NULL;
    int err = 0;
    struct oe_addrinfo* head = NULL;
    struct oe_addrinfo* tail = NULL;
    struct oe_addrinfo* p = NULL;

    OE_UNUSED(resolv);

    if (res)
        *res = NULL;

    if (!res)
    {
        OE_TRACE_ERROR("invalid parameters");
        goto done;
    }

    /* Get the handle for enumerating addrinfo structures. */
    {
        oe_result_t result;

        if ((result = oe_posix_getaddrinfo_open_ocall(
                 &handle, node, service, (struct addrinfo*)hints, &err)) !=
            OE_OK)
        {
            OE_TRACE_ERROR(
                "oe_posix_getaddrinfo_open_ocall(): result=%s",
                oe_result_str(result));
            goto done;
        }

        if (!handle)
        {
            OE_TRACE_ERROR("handle=null");
            goto done;
        }
    }

    /* Enumerate addrinfo structures. */
    for (;;)
    {
        int retval = 0;
        int err = 0;
        size_t canonnamelen = 0;
        oe_result_t result;

        if (!(p = oe_calloc(1, sizeof(struct oe_addrinfo))))
        {
            OE_TRACE_ERROR("oe_calloc() failed");
            goto done;
        }

        /* Determine required size ai_addr and ai_canonname buffers. */
        if ((result = oe_posix_getaddrinfo_read_ocall(
                 &retval,
                 handle,
                 &p->ai_flags,
                 &p->ai_family,
                 &p->ai_socktype,
                 &p->ai_protocol,
                 p->ai_addrlen,
                 &p->ai_addrlen,
                 NULL, /* ai_addr */
                 canonnamelen,
                 &canonnamelen,
                 NULL, /* ai_canonname */
                 &err)) != OE_OK)
        {
            OE_TRACE_ERROR(
                "oe_posix_getaddrinfo_read_ocall(): result=%s",
                oe_result_str(result));
            goto done;
        }

        /* If this is the final element in the enumeration. */
        if (retval == 1)
            break;

        /* Expecting that addr and canonname buffers were too small. */
        if (retval != -1 || err != ENAMETOOLONG)
        {
            OE_TRACE_ERROR("oe_posix_getaddrinfo_read_ocall() failed");
            goto done;
        }

        if (p->ai_addrlen && !(p->ai_addr = oe_calloc(1, p->ai_addrlen)))
        {
            OE_TRACE_ERROR("oe_calloc() failed");
            goto done;
        }

        if (canonnamelen && !(p->ai_canonname = oe_calloc(1, canonnamelen)))
        {
            OE_TRACE_ERROR("oe_calloc() failed");
            goto done;
        }

        if ((result = oe_posix_getaddrinfo_read_ocall(
                 &retval,
                 handle,
                 &p->ai_flags,
                 &p->ai_family,
                 &p->ai_socktype,
                 &p->ai_protocol,
                 p->ai_addrlen,
                 &p->ai_addrlen,
                 (struct sockaddr*)p->ai_addr,
                 canonnamelen,
                 &canonnamelen,
                 p->ai_canonname,
                 &err)) != OE_OK)
        {
            OE_TRACE_ERROR(
                "oe_posix_getaddrinfo_read_ocall(): result=%s",
                oe_result_str(result));
            goto done;
        }

        /* Append to the list. */
        if (tail)
        {
            tail->ai_next = p;
            tail = p;
        }
        else
        {
            head = p;
            tail = p;
        }

        p = NULL;
    }

    /* Close the enumeration. */
    if (handle)
    {
        int retval = -1;
        int err = 0;
        oe_result_t result;

        if ((result = oe_posix_getaddrinfo_close_ocall(
                 &retval, handle, &err)) != OE_OK)
        {
            OE_TRACE_ERROR(
                "oe_posix_getaddrinfo_read_ocall(): result=%s",
                oe_result_str(result));
            goto done;
        }

        handle = NULL;

        if (retval != 0)
        {
            OE_TRACE_ERROR(
                "oe_posix_getaddrinfo_read_ocall(): retval=%d", retval);
            goto done;
        }
    }

    /* If the list is empty. */
    if (!head)
    {
        OE_TRACE_ERROR("empty enumeration");
        goto done;
    }

    *res = head;
    head = NULL;
    tail = NULL;
    ret = 0;

done:

    if (handle)
    {
        int retval;
        int err;
        oe_posix_getaddrinfo_close_ocall(&retval, handle, &err);
    }

    if (head)
        oe_freeaddrinfo(head);

    if (p)
        oe_freeaddrinfo(p);

    return ret;
}

static int _hostresolv_shutdown(oe_resolver_t* resolv_)
{
    int ret = -1;
    resolv_t* resolv = _cast_resolv(resolv_);
    oe_result_t result = OE_FAILURE;

    oe_errno = 0;

    if (!resolv)
    {
        oe_errno = EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    if ((result = oe_posix_shutdown_resolver_device_ocall(&ret, &oe_errno)) !=
        OE_OK)
    {
        oe_errno = EINVAL;
        OE_TRACE_ERROR("%s oe_errno=%d", oe_result_str(result), oe_errno);
        goto done;
    }

    /* Release the resolv_ object. */
    oe_free(resolv);
    ret = 0;
done:
    return ret;
}

// clang-format off
static oe_resolver_ops_t _ops =
{
    .getaddrinfo = _hostresolv_getaddrinfo,
    .getnameinfo = _hostresolv_getnameinfo,
    .shutdown = _hostresolv_shutdown
};
// clang-format on

// clang-format off
static resolv_t _hostresolv =
{
    .base.type = OE_RESOLVER_HOST,
    .base.size = sizeof(resolv_t),
    .base.ops = &_ops,
    .magic = RESOLV_MAGIC
};
// clang-format on

oe_result_t oe_load_module_hostresolver(void)
{
    oe_result_t result = OE_FAILURE;
    static bool _loaded = false;
    static oe_spinlock_t _lock = OE_SPINLOCK_INITIALIZER;
    int ret = -1;

    if (!_loaded)
    {
        oe_spin_lock(&_lock);

        if (!_loaded)
        {
            oe_resolver_t* resolver = &_hostresolv.base;

            if ((ret = oe_register_resolver(2, resolver)) != 0)
            {
                OE_TRACE_ERROR("ret=%d", ret);
                goto done;
            }
        }
        oe_spin_unlock(&_lock);
    }
    result = OE_OK;
done:
    return result;
}
