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
#include <openenclave/internal/typeinfo.h>
#include <openenclave/bits/module.h>
#include <openenclave/internal/trace.h>
#include "oe_t.h"

/*
**==============================================================================
**
** struct oe_addrinfo type information.
**
**==============================================================================
*/

// clang-format off

extern oe_struct_type_info_t __oe_addrinfo_sti;

typedef struct oe_addrinfo oe_addrinfo_t;

static oe_field_type_info_t _oe_addrinfo_ftis[] =
{
    OE_FTI_ARRAY(oe_addrinfo_t, ai_addr, sizeof(uint8_t), ai_addrlen),
    OE_FTI_STRUCT(oe_addrinfo_t, ai_next, oe_addrinfo_t, &__oe_addrinfo_sti),
    OE_FTI_STRING(oe_addrinfo_t, ai_canonname),
};

oe_struct_type_info_t __oe_addrinfo_sti =
{
    .struct_size = sizeof(struct oe_addrinfo),
    _oe_addrinfo_ftis,
    OE_COUNTOF(_oe_addrinfo_ftis),
};

// clang-format on

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

//
// We try return the sockaddr if it fits, but if it doesn't we return
// OE_EAI_OVERFLOW and the required size. IF the buffer is overflowed the caller
// needs to try _hostresolv_getaddrinfo with a suitably reallocated buffer
//
static int _hostresolv_getaddrinfo_r(
    oe_resolver_t* resolv,
    const char* node,
    const char* service,
    const struct oe_addrinfo* hints,
    struct oe_addrinfo* res_out,
    size_t* required_size_in_out)
{
    int ret = OE_EAI_FAIL;
    int retval;
    struct oe_addrinfo* res = NULL;
    oe_struct_type_info_t* structure = &__oe_addrinfo_sti;
    oe_result_t result = OE_FAILURE;
    OE_UNUSED(resolv);

    oe_errno = 0;
    if ((result = oe_posix_getaddrinfo_ocall(
             &retval,
             node,
             service,
             (const struct addrinfo*)hints,
             (struct addrinfo**)&res,
             &oe_errno)) != OE_OK)
    {
        oe_errno = EINVAL;
        OE_TRACE_ERROR("%s retval=%d", oe_result_str(result), retval);
        goto done;
    }

    if (retval != 0)
    {
        ret = retval;
        OE_TRACE_ERROR("ret=%d", ret);
        goto done;
    }

    /* Clone the result to caller's memory. */
    {
        oe_result_t result = OE_FAILURE;

        if ((result = oe_type_info_clone(
                 structure, res, res_out, required_size_in_out)) == OE_OK)
        {
            ret = 0;
            goto done;
        }

        if (result == OE_BUFFER_TOO_SMALL)
            ret = OE_EAI_OVERFLOW;
        else
            ret = OE_EAI_FAIL;

        OE_TRACE_ERROR("%s ret=%d", oe_result_str(result), ret);
    }

done:
    if (res)
    {
        /* Ask host to release the result buffer. */
        if ((result = oe_posix_freeaddrinfo_ocall((struct addrinfo*)res)) !=
            OE_OK)
        {
            OE_TRACE_ERROR("%s", oe_result_str(result));
        }
    }

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

static oe_resolver_ops_t _ops = {.getaddrinfo_r = _hostresolv_getaddrinfo_r,
                                 .getnameinfo = _hostresolv_getnameinfo,
                                 .shutdown = _hostresolv_shutdown};

static resolv_t _hostresolv = {.base.type = OE_RESOLVER_HOST,
                               .base.size = sizeof(resolv_t),
                               .base.ops = &_ops,
                               .magic = RESOLV_MAGIC};

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
