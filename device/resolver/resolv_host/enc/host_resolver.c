// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#define _GNU_SOURCE

// clang-format off
#include <openenclave/enclave.h>
// clang-format on

#include <openenclave/internal/device.h>
#include <openenclave/corelibc/sys/socket.h>
#include <openenclave/corelibc/netdb.h>
#include <openenclave/internal/host_resolver.h>
#include <openenclave/internal/resolver.h>
#include <openenclave/bits/safemath.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/thread.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/hostbatch.h>
#include "../common/hostresolvargs.h"
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/corelibc/string.h>

// The host resolver is not actually a device in the file descriptor sense.

#define DEVICE_ID_HOST_RESOLVER 42
/*
**==============================================================================
**
** host batch:
**
**==============================================================================
*/

oe_device_t* oe_get_hostresolv(void);
static oe_host_batch_t* _host_batch;
static oe_spinlock_t _lock;
void* memcpy(void* dst, const void* src, size_t len);

static void _atexit_handler()
{
    oe_spin_lock(&_lock);
    oe_host_batch_delete(_host_batch);
    _host_batch = NULL;
    oe_spin_unlock(&_lock);
}

static oe_host_batch_t* _get_host_batch(void)
{
    const size_t BATCH_SIZE = sizeof(oe_hostresolv_args_t) + OE_BUFSIZ;

    if (_host_batch == NULL)
    {
        oe_spin_lock(&_lock);

        if (_host_batch == NULL)
        {
            _host_batch = oe_host_batch_new(BATCH_SIZE);
            oe_atexit(_atexit_handler);
        }

        oe_spin_unlock(&_lock);
    }

    return _host_batch;
}

/*
**==============================================================================
**
** hostresolv operations:
**
**==============================================================================
*/

#define RESOLV_MAGIC 0x536f636b

typedef oe_hostresolv_args_t args_t;

typedef struct _resolv
{
    struct _oe_resolver base;
    uint32_t magic;
} resolv_t;

static resolv_t* _cast_resolv(const oe_resolver_t* device)
{
    resolv_t* resolv = (resolv_t*)device;

    if (resolv == NULL || resolv->magic != RESOLV_MAGIC)
        return NULL;

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
    ssize_t ret = OE_EAI_FAIL;
    args_t* args = NULL;
    oe_host_batch_t* batch = _get_host_batch();
    (void)dev;

    oe_errno = 0;

    if (!batch)
    {
        oe_errno = EINVAL;
        goto done;
    }

    if (!host && !serv)
    {
        oe_errno = EINVAL;
        goto done;
    }

    if (!(hostlen > 0) && !(servlen > 0))
    {
        oe_errno = EINVAL;
        goto done;
    }

    /* Input */
    {
        // With a buffer big enough for a single addrinfo

        size_t required = (size_t)salen + (size_t)hostlen + (size_t)servlen;
        if ((hostlen + servlen + 2) > salen)
        {
            required = hostlen + servlen + 2;
        }
        if (!(args = oe_host_batch_calloc(batch, sizeof(args_t) + required)))
        {
            oe_errno = ENOMEM;
            goto done;
        }

        if (sa->sa_family == OE_AF_HOST)
        {
            ((struct oe_sockaddr*)sa)->sa_family = OE_AF_INET;
        }

        //    int64_t ret;
        //    socklen_t addrlen; // in
        //    // struct oe_sockaddr *addr;  data in buf
        //    socklen_t hostlen;
        // Hostname returned in buf
        // socklen_t servlen;
        // Service name returned in buf+hostlen after hostname
        //  int32_t flags;

        args->op = OE_HOSTRESOLV_OP_GETNAMEINFO;
        args->u.getnameinfo.ret = -1;
        args->u.getnameinfo.addrlen = (int32_t)salen;
        args->u.getnameinfo.hostlen = (int32_t)hostlen;
        args->u.getnameinfo.flags = (int32_t)flags;
        memcpy(args->buf, sa, (size_t)salen);
    }

    /* Call */
    {
        if (oe_ocall(OE_OCALL_HOSTRESOLVER, (uint64_t)args, NULL) != OE_OK)
        {
            oe_errno = EINVAL;
            goto done;
        }

        if (args->u.getnameinfo.ret < 0)
        {
            // If the error is OE_EAI_OVERFLOW. If not, we need to walk the
            // structure to see how much space it needs

            oe_errno = args->err;
            ret = args->u.getaddrinfo.ret;
            goto done;
        }
        ret = args->u.getaddrinfo.ret;
    }
    /* Output */
    {
        uint8_t* bufptr = args->buf;
        // We always pass at least a zero length node and service.
        if (hostlen > 0)
        {
            hostlen = (socklen_t)oe_strnlen((const char*)bufptr, hostlen - 1);
            memcpy(host, bufptr, (size_t)hostlen);
            bufptr[hostlen] = '\0';
            bufptr += hostlen + 1;
        }

        if (servlen > 0)
        {
            servlen = (socklen_t)oe_strnlen((const char*)bufptr, servlen - 1);
            memcpy(serv, bufptr, (size_t)servlen);
            bufptr[servlen] = '\0';
        }
    }
done:
    return ret;
}

//
// We try return the sockaddr if it fits, but if it doesn't we return
// OE_EAI_OVERFLOW and the required size. IF the buffer is overflowed the caller
// needs to try _hostresolv_getaddrinfo with a suitably reallocated buffer
//
static ssize_t _hostresolv_getaddrinfo_r(
    oe_resolver_t* resolv,
    const char* node,
    const char* service,
    const struct oe_addrinfo* hints,
    struct oe_addrinfo* res,
    ssize_t* required_size)
{
    ssize_t ret = OE_EAI_FAIL;
    args_t* args = NULL;
    oe_host_batch_t* batch = _get_host_batch();

    oe_errno = 0;
    (void)resolv;

    if (!batch)
    {
        oe_errno = EINVAL;
        goto done;
    }

    if (!node && !service)
    {
        oe_errno = EINVAL;
        goto done;
    }

    size_t nodelen = (node) ? oe_strlen(node) : 0;
    size_t servicelen = (service) ? oe_strlen(service) : 0;

    if (!(nodelen > 0) && !(servicelen > 0))
    {
        oe_errno = EINVAL;
        goto done;
    }

    /* Input */
    {
        // With a buffer big enough for a single addrinfo

        if (!(args = oe_host_batch_calloc(
                  batch, sizeof(args_t) + (size_t)*required_size)))
        {
            oe_errno = ENOMEM;
            goto done;
        }

        args->op = OE_HOSTRESOLV_OP_GETADDRINFO;
        args->u.getaddrinfo.ret = -1;

        // We always pass at least a zero length node and service.
        if (nodelen > 0)
        {
            memcpy(args->buf, node, (size_t)nodelen);
            args->buf[nodelen] = '\0';
            args->u.getaddrinfo.nodelen = (int32_t)nodelen;
        }
        else
        {
            args->buf[0] = '\0';
            args->u.getaddrinfo.nodelen = 0;
        }

        if (servicelen > 0)
        {
            memcpy(args->buf + nodelen + 1, service, (size_t)servicelen);
            args->buf[nodelen + 1 + servicelen] = '\0';
            args->u.getaddrinfo.servicelen = (int32_t)servicelen;
        }
        else
        {
            args->buf[nodelen + 1 + servicelen] = '\0';
            args->u.getaddrinfo.servicelen = 0;
        }

        if (hints)
        {
            args->u.getaddrinfo.hint_flags = hints->ai_flags;
            args->u.getaddrinfo.hint_family = hints->ai_family;
            args->u.getaddrinfo.hint_socktype = hints->ai_socktype;
            args->u.getaddrinfo.hint_protocol = hints->ai_protocol;
        }
        else
        {
            args->u.getaddrinfo.hint_flags =
                (OE_AI_V4MAPPED | OE_AI_ADDRCONFIG);
            args->u.getaddrinfo.hint_family = OE_AF_UNSPEC;
            args->u.getaddrinfo.hint_socktype = 0;
            args->u.getaddrinfo.hint_protocol = 0;
        }
        args->u.getaddrinfo.buffer_len =
            (int32_t)required_size; // pass down the buffer that is available.
                                    // It is likely enough
    }

    /* Call */
    {
        if (oe_ocall(OE_OCALL_HOSTRESOLVER, (uint64_t)args, NULL) != OE_OK)
        {
            oe_errno = EINVAL;
            goto done;
        }

        if (args->u.getaddrinfo.ret < 0)
        {
            // If the error is OE_EAI_OVERFLOW. If not, we need to walk the
            // structure to see how much space it needs

            oe_errno = args->err;
            ret = args->u.getaddrinfo.ret;
            goto done;
        }
        ret = args->u.getaddrinfo.ret;
    }

    /* Output */
    {
        struct oe_addrinfo* thisinfo = (struct oe_addrinfo*)args->buf;
        size_t buffer_required = (size_t)0;

        // Allocate host memory and copy the chain of addrinfos

        do
        {
            buffer_required += sizeof(struct oe_addrinfo);
            if (thisinfo->ai_addr)
            {
                buffer_required += sizeof(struct oe_sockaddr);
            }
            if (thisinfo->ai_canonname)
            {
                buffer_required += oe_strlen(thisinfo->ai_canonname) + 1;
            }

            thisinfo = thisinfo->ai_next;

        } while (thisinfo != NULL);

        if ((ssize_t)buffer_required > *required_size)
        {
            *required_size = (ssize_t)buffer_required;
            return OE_EAI_OVERFLOW;
        }
        else
        {
            size_t canon_namelen = 0;
            uint8_t* bufptr = (uint8_t*)res;
            thisinfo = (struct oe_addrinfo*)args->buf;
            do
            {
                // Set up the pointers in the destination structure to point
                // at the buffer after the addrinfo structure.
                struct oe_addrinfo* buf_info = (struct oe_addrinfo*)bufptr;
                buf_info->ai_flags = thisinfo->ai_flags;
                buf_info->ai_family = thisinfo->ai_family;
                buf_info->ai_socktype = thisinfo->ai_socktype;
                buf_info->ai_protocol = thisinfo->ai_protocol;
                buf_info->ai_addrlen = thisinfo->ai_addrlen;
                buf_info->ai_canonname = NULL;
                buf_info->ai_addr = NULL;
                buf_info->ai_next = NULL;

                bufptr += sizeof(struct oe_addrinfo);
                if (thisinfo->ai_addr)
                {
                    buf_info->ai_addr = (struct oe_sockaddr*)(bufptr);
                    memcpy(
                        buf_info->ai_addr,
                        thisinfo->ai_addr,
                        buf_info->ai_addrlen);
                    bufptr += buf_info->ai_addrlen;
                }
                if (thisinfo->ai_canonname)
                {
                    canon_namelen = oe_strlen(thisinfo->ai_canonname) + 1;
                    buf_info->ai_canonname = (char*)bufptr;
                    memcpy(
                        buf_info->ai_canonname,
                        thisinfo->ai_canonname,
                        canon_namelen);
                    bufptr += canon_namelen;
                }

                thisinfo = thisinfo->ai_next;
                if (thisinfo)
                {
                    buf_info->ai_next = (struct oe_addrinfo*)bufptr;
                }

            } while (thisinfo != NULL);
        }
    }

done:

    if (args)
        oe_host_batch_free(batch);

    return ret;
}

static int _hostresolv_shutdown(oe_resolver_t* resolv_)
{
    int ret = -1;
    resolv_t* resolv = _cast_resolv(resolv_);
    oe_host_batch_t* batch = _get_host_batch();
    args_t* args = NULL;

    oe_errno = 0;

    /* Check parameters. */
    if (!resolv_ || !batch)
    {
        oe_errno = EINVAL;
        goto done;
    }

    /* Input */
    {
        if (!(args = oe_host_batch_calloc(batch, sizeof(args_t))))
        {
            oe_errno = ENOMEM;
            goto done;
        }

        args->op = OE_HOSTRESOLV_OP_SHUTDOWN;
        args->u.shutdown_device.ret = -1;
    }

    /* Call */
    {
        if (oe_ocall(OE_OCALL_HOSTRESOLVER, (uint64_t)args, NULL) != OE_OK)
        {
            oe_errno = EINVAL;
            goto done;
        }

        if (args->u.shutdown_device.ret != 0)
        {
            oe_errno = args->err;
            goto done;
        }
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

oe_resolver_t* oe_get_hostresolver(void)
{
    return &_hostresolv.base;
}
