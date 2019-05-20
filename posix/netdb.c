// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/corelibc/netdb.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/corelibc/sys/socket.h>
#include <openenclave/internal/posix/raise.h>
#include <openenclave/internal/posix/resolver.h>
#include <openenclave/internal/thread.h>
#include <openenclave/internal/trace.h>

static oe_resolver_t* _resolver;
static oe_spinlock_t _lock = OE_SPINLOCK_INITIALIZER;
static bool _installed_atexit_handler = false;

static void _atexit_handler(void)
{
    if (_resolver)
        _resolver->ops->release(_resolver);
}

/* Called by the public oe_load_module_host_resolver() function. */
int oe_register_resolver(oe_resolver_t* resolver)
{
    int ret = -1;
    bool locked = false;

    /* Check parameters. */
    if (!resolver || !resolver->ops || !resolver->ops->getaddrinfo ||
        !resolver->ops->getnameinfo)
    {
        OE_RAISE_ERRNO(OE_EINVAL);
    }

    oe_spin_lock(&_lock);
    locked = true;

    /* This function can be called only once. */
    if (_resolver != NULL)
        OE_RAISE_ERRNO(OE_EINVAL);

    _resolver = resolver;

    if (!_installed_atexit_handler)
    {
        oe_atexit(_atexit_handler);
        _installed_atexit_handler = true;
    }

    ret = 0;

done:

    if (locked)
        oe_spin_unlock(&_lock);

    return ret;
}

int oe_getaddrinfo(
    const char* node,
    const char* service,
    const struct oe_addrinfo* hints,
    struct oe_addrinfo** res_out)
{
    int ret = OE_EAI_FAIL;
    struct oe_addrinfo* res;
    bool locked = false;

    if (res_out)
        *res_out = NULL;

    if (!_resolver)
        OE_RAISE_ERRNO(OE_EINVAL);

    oe_spin_lock(&_lock);
    locked = true;

    if ((*_resolver->ops->getaddrinfo)(_resolver, node, service, hints, &res) ==
        0)
    {
        *res_out = res;
        ret = 0;
        goto done;
    }

done:

    if (locked)
        oe_spin_unlock(&_lock);

    return ret;
}

int oe_getnameinfo(
    const struct oe_sockaddr* sa,
    oe_socklen_t salen,
    char* host,
    oe_socklen_t hostlen,
    char* serv,
    oe_socklen_t servlen,
    int flags)
{
    ssize_t ret = -1;
    bool locked = false;

    if (!_resolver)
        OE_RAISE_ERRNO(OE_EINVAL);

    oe_spin_lock(&_lock);
    locked = true;

    ret = (*_resolver->ops->getnameinfo)(
        _resolver, sa, salen, host, hostlen, serv, servlen, flags);

done:

    if (locked)
        oe_spin_unlock(&_lock);

    return (int)ret;
}

void oe_freeaddrinfo(struct oe_addrinfo* res)
{
    struct oe_addrinfo* p;

    for (p = res; p;)
    {
        struct oe_addrinfo* next = p->ai_next;

        oe_free(p->ai_addr);
        oe_free(p->ai_canonname);
        oe_free(p);

        p = next;
    }
}
