// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
#include <openenclave/corelibc/netdb.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/corelibc/sys/socket.h>
#include <openenclave/internal/resolver.h>
#include <openenclave/internal/trace.h>

static size_t _resolver_table_len = 3;
static oe_resolver_t* _resolver_table[3] = {0}; // At most 3

/* Called by the public oe_load_module_hostresolver() function. */
int oe_register_resolver(int resolver_priority, oe_resolver_t* presolver)
{
    int ret = -1;

    if (presolver == NULL)
    {
        oe_errno = EINVAL;
        OE_TRACE_ERROR("oe_errno =%d  ", oe_errno);
        ret = oe_errno;
        goto done;
    }

    if (resolver_priority >= (int)_resolver_table_len)
    {
        oe_errno = EINVAL;
        OE_TRACE_ERROR(
            "oe_errno =%d  : resolver_priority=%d _resolver_table_len=%ld",
            oe_errno,
            resolver_priority,
            _resolver_table_len);
        goto done;
    }
    _resolver_table[resolver_priority] = presolver;
    ret = 0;
done:
    return ret;
}

size_t oe_debug_malloc_check();

int oe_getaddrinfo(
    const char* node,
    const char* service,
    const struct oe_addrinfo* hints,
    struct oe_addrinfo** res)
{
    size_t resolver_idx = 0;
    ssize_t ret = -1;
    // ATTN:IO: the following size calculation seems to assume there will be
    // only one set of addrinfo returned, not good
    size_t required_size = (size_t)(
        sizeof(struct oe_addrinfo) + sizeof(struct oe_sockaddr) +
        256); // 255+1 for canonname
    struct oe_addrinfo* retinfo = NULL;

    if (!(retinfo = oe_calloc(1, required_size)))
    {
        OE_TRACE_ERROR("oe_calloc failed required_size=%ld", required_size);
        goto done;
    }

    for (resolver_idx = 0; resolver_idx < _resolver_table_len; resolver_idx++)
    {
        if (_resolver_table[resolver_idx] != NULL)
        {
            ret = (*_resolver_table[resolver_idx]->ops->getaddrinfo_r)(
                _resolver_table[resolver_idx],
                node,
                service,
                hints,
                retinfo,
                &required_size);
            switch (ret)
            {
                case OE_EAI_BADFLAGS:
                case OE_EAI_NONAME:
                case OE_EAI_AGAIN:
                case OE_EAI_FAIL:
                case OE_EAI_FAMILY:
                case OE_EAI_SOCKTYPE:
                case OE_EAI_SERVICE:
                case OE_EAI_MEMORY:
                case OE_EAI_SYSTEM:
                case OE_EAI_NODATA:
                case OE_EAI_ADDRFAMILY:
                case OE_EAI_INPROGRESS:
                case OE_EAI_CANCELED:
                case OE_EAI_NOTCANCELED:
                case OE_EAI_INTR:
                case OE_EAI_IDN_ENCODE:
                    // This says we failed to find the name. Try the next
                    // resolver .
                    continue;

                case 0:
                case OE_EAI_ALLDONE:
                {
                    *res = retinfo;
                    retinfo = NULL;
                    goto done;
                }

                case OE_EAI_OVERFLOW:
                {
                    struct oe_addrinfo* ptr;

                    if (!(ptr = oe_realloc(retinfo, (size_t)required_size)))
                    {
                        OE_TRACE_ERROR(
                            "oe_realloc failed required_size=%ld",
                            required_size);
                        oe_free(retinfo);
                        goto done;
                    }

                    retinfo = ptr;

                    ret = (*_resolver_table[resolver_idx]->ops->getaddrinfo_r)(
                        _resolver_table[resolver_idx],
                        node,
                        service,
                        hints,
                        retinfo,
                        &required_size);
                    if (ret == 0 || ret == OE_EAI_ALLDONE)
                    {
                        *res = retinfo;
                        retinfo = NULL;
                        goto done;
                    }
                }
            }
        }
    }
    OE_TRACE_ERROR("oe_getaddrinfo failed");

done:

    if (retinfo)
        oe_free(retinfo);

    return (int)ret;
}

void oe_freeaddrinfo(struct oe_addrinfo* res)
{
    if (res != NULL)
        oe_free(res);
}

int oe_getnameinfo(
    const struct oe_sockaddr* sa,
    socklen_t salen,
    char* host,
    socklen_t hostlen,
    char* serv,
    socklen_t servlen,
    int flags)

{
    size_t resolver_idx = 0;
    ssize_t ret = -1;

    for (resolver_idx = 0; resolver_idx < _resolver_table_len; resolver_idx++)
    {
        if (_resolver_table[resolver_idx] != NULL)
        {
            ret = (*_resolver_table[resolver_idx]->ops->getnameinfo)(
                _resolver_table[resolver_idx],
                sa,
                salen,
                host,
                hostlen,
                serv,
                servlen,
                flags);
            if (ret == 0)
                goto done;
        }
    }
    OE_TRACE_ERROR("oe_getnameinfo failed");
done:
    return (int)ret;
}
