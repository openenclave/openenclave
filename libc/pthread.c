// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

// TODO: oelibc should not depend on SGX-specifc headers
#include <openenclave/bits/sgx/sgxtypes.h>
#include <openenclave/corelibc/pthread.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/defs.h>
#include <openenclave/internal/pthreadhooks.h>
#include <openenclave/internal/sgx/td.h>
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

OE_STATIC_ASSERT(sizeof(struct __pthread) <= OE_THREAD_LOCAL_SPACE);
OE_STATIC_ASSERT(sizeof(pthread_once_t) == sizeof(oe_once_t));
OE_STATIC_ASSERT(sizeof(pthread_spinlock_t) == sizeof(oe_spinlock_t));
OE_STATIC_ASSERT(sizeof(pthread_mutex_t) >= sizeof(oe_mutex_t));
OE_STATIC_ASSERT(sizeof(pthread_cond_t) >= sizeof(oe_cond_t));
OE_STATIC_ASSERT(sizeof(pthread_rwlock_t) >= sizeof(oe_rwlock_t));

static __thread struct __pthread _pthread_self = {.locale = C_LOCALE};

pthread_t __pthread_self()
{
    return &_pthread_self;
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
