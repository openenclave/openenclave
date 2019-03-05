// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
#include <openenclave/corelibc/netdb.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/corelibc/sys/socket.h>
#include <openenclave/internal/resolver.h>

static size_t _resolver_table_len = 3;
static oe_resolver_t* _resolver_table[3] = {0}; // At most 3

int oe_register_resolver(int resolver_priority, oe_resolver_t* presolver)

{
    if (resolver_priority > (int)_resolver_table_len)
    {
        oe_errno = EINVAL;
        return -1;
    }

    _resolver_table[resolver_priority] = presolver;
    return 0;
}

size_t oe_debug_malloc_check();
int oe_getaddrinfo(
    const char* node,
    const char* service,
    const struct oe_addrinfo* hints,
    struct oe_addrinfo** res)

{
    size_t resolver_idx = 0;
    ssize_t rslt = -1;
    ssize_t required_size = (ssize_t)(
        sizeof(struct oe_addrinfo) + sizeof(struct oe_sockaddr) +
        256); // 255+1 for canonname
    struct oe_addrinfo* retinfo =
        (struct oe_addrinfo*)oe_calloc(1, (size_t)required_size);

    for (resolver_idx = 0; resolver_idx < _resolver_table_len; resolver_idx++)
    {
        if (_resolver_table[resolver_idx] != NULL)
        {
            rslt = (*_resolver_table[resolver_idx]->ops->getaddrinfo_r)(
                _resolver_table[resolver_idx],
                node,
                service,
                hints,
                retinfo,
                &required_size);
            switch (rslt)
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
                    *res = retinfo;
                    return (int)rslt;

                case OE_EAI_OVERFLOW:
                    retinfo = oe_realloc(retinfo, (size_t)required_size);
                    rslt = (*_resolver_table[resolver_idx]->ops->getaddrinfo_r)(
                        _resolver_table[resolver_idx],
                        node,
                        service,
                        hints,
                        retinfo,
                        &required_size);
                    if (rslt == 0 || rslt == OE_EAI_ALLDONE)
                    {
                        *res = retinfo;
                    }
                    return (int)rslt;
            }
        }
    }

    oe_free(retinfo); // We got nothing
    return (int)rslt;
}

void oe_freeaddrinfo(struct oe_addrinfo* res)

{
    if (res != NULL)
    {
        oe_free(res);
    }
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
    ssize_t rslt = -1;

    for (resolver_idx = 0; resolver_idx < _resolver_table_len; resolver_idx++)
    {
        if (_resolver_table[resolver_idx] != NULL)
        {
            rslt = (*_resolver_table[resolver_idx]->ops->getnameinfo)(
                _resolver_table[resolver_idx],
                sa,
                salen,
                host,
                hostlen,
                serv,
                servlen,
                flags);
            if (rslt == 0)
            {
                return (int)rslt;
            }
        }
    }
    return (int)rslt;
}
