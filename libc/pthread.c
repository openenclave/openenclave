// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/corelibc/pthread.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/defs.h>
#include <openenclave/internal/pthreadhooks.h>
#include <openenclave/internal/sgxtypes.h>
#include <openenclave/internal/thread.h>
#include <pthread.h>

#ifdef pthread_equal
#undef pthread_equal
#endif

#if !defined(OE_NEED_STDC_NAMES)
#define OE_NEED_STDC_NAMES
#define __UNDEF_OE_NEED_STDC_NAMES
#endif
#if defined(OE_INLINE)
#undef OE_INLINE
#define OE_INLINE
#endif
#include <openenclave/corelibc/bits/pthread_cond.h>
#include <openenclave/corelibc/bits/pthread_equal.h>
#include <openenclave/corelibc/bits/pthread_key.h>
#include <openenclave/corelibc/bits/pthread_mutex.h>
#include <openenclave/corelibc/bits/pthread_once.h>
#include <openenclave/corelibc/bits/pthread_rwlock.h>
#include <openenclave/corelibc/bits/pthread_spin.h>
#if defined(__UNDEF_OE_NEED_STDC_NAMES)
#undef OE_NEED_STDC_NAMES
#undef __UNDEF_OE_NEED_STDC_NAMES
#endif

#include "locale_impl.h"
#include "pthread_impl.h"

#ifdef pthread
#undef pthread
#endif

OE_STATIC_ASSERT(sizeof(struct __pthread) <= sizeof(((td_t*)NULL)->pthread));
OE_STATIC_ASSERT(sizeof(pthread_once_t) == sizeof(oe_once_t));
OE_STATIC_ASSERT(sizeof(pthread_spinlock_t) == sizeof(oe_spinlock_t));
OE_STATIC_ASSERT(sizeof(pthread_mutex_t) >= sizeof(oe_mutex_t));
OE_STATIC_ASSERT(sizeof(pthread_cond_t) >= sizeof(oe_cond_t));
OE_STATIC_ASSERT(sizeof(pthread_rwlock_t) >= sizeof(oe_rwlock_t));

static void _pthread_self_init()
{
    td_t* td = oe_get_td();

    if (td)
    {
        struct __pthread* self = (struct __pthread*)td->pthread;
        memset(self, 0, sizeof(struct __pthread));
        self->locale = C_LOCALE;
    }
}

pthread_t __pthread_self()
{
    static oe_once_t _once = OE_ONCE_INITIALIZER;
    td_t* td;

    if (oe_once(&_once, _pthread_self_init) != 0)
        return NULL;

    if (!(td = oe_get_td()))
        return NULL;

    struct __pthread* self = (struct __pthread*)td->pthread;

    return self;
}

OE_WEAK_ALIAS(__pthread_self, pthread_self);

static oe_pthread_hooks_t* _pthread_hooks;

void oe_register_pthread_hooks(oe_pthread_hooks_t* pthread_hooks)
{
    _pthread_hooks = pthread_hooks;
}

int pthread_create(
    pthread_t* thread,
    const pthread_attr_t* attr,
    void* (*start_routine)(void*),
    void* arg)
{
    if (!_pthread_hooks || !_pthread_hooks->create)
    {
        oe_assert("pthread_create(): panic" == NULL);
        return -1;
    }

    return _pthread_hooks->create(thread, attr, start_routine, arg);
}

int pthread_join(pthread_t thread, void** retval)
{
    if (!_pthread_hooks || !_pthread_hooks->join)
    {
        oe_assert("pthread_join(): panic" == NULL);
        return -1;
    }

    return _pthread_hooks->join(thread, retval);
}

int pthread_detach(pthread_t thread)
{
    if (!_pthread_hooks || !_pthread_hooks->detach)
    {
        oe_assert("pthread_detach(): panic" == NULL);
        return -1;
    }

    return _pthread_hooks->detach(thread);
}
