// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

// TODO: oelibc should not depend on SGX-specifc headers
#include <openenclave/bits/sgx/sgxtypes.h>
#include <openenclave/corelibc/pthread.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/defs.h>
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

pthread_t __get_tp()
{
    return &_pthread_self;
}

pthread_t pthread_self()
{
    return &_pthread_self;
}

int pthread_create(
    pthread_t* thread,
    const pthread_attr_t* attr,
    void* (*start_routine)(void*),
    void* arg)
{
    return oe_pthread_create(
        (oe_pthread_t*)thread,
        (const oe_pthread_attr_t*)attr,
        start_routine,
        arg);
}

int pthread_join(pthread_t thread, void** retval)
{
    return oe_pthread_join((oe_pthread_t)thread, retval);
}

int pthread_detach(pthread_t thread)
{
    return oe_pthread_detach((oe_pthread_t)thread);
}

OE_NO_RETURN
void pthread_exit(void* retval)
{
    oe_pthread_exit(retval);
    oe_abort();
}

int pthread_attr_init(pthread_attr_t* attr)
{
    return oe_pthread_attr_init((oe_pthread_attr_t*)attr);
}

int pthread_attr_destroy(pthread_attr_t* attr)
{
    return oe_pthread_attr_destroy((oe_pthread_attr_t*)attr);
}

int pthread_attr_setdetachstate(pthread_attr_t* attr, int detachstate)
{
    ((oe_pthread_attr_t*)attr)->detachstate =
        (detachstate == PTHREAD_CREATE_DETACHED);
    return 0;
}

OE_EXPORT int pthread_mutex_destroy(pthread_mutex_t* m)
{
    return oe_pthread_mutex_destroy((oe_pthread_mutex_t*)m);
}

OE_EXPORT
int pthread_mutex_init(pthread_mutex_t* m, const pthread_mutexattr_t* attr)
{
    return oe_pthread_mutex_init(
        (oe_pthread_mutex_t*)m, (const oe_pthread_mutexattr_t*)attr);
}

OE_EXPORT
int pthread_mutex_lock(pthread_mutex_t* m)
{
    return oe_pthread_mutex_lock((oe_pthread_mutex_t*)m);
}

OE_EXPORT int pthread_mutex_unlock(pthread_mutex_t* m)
{
    return oe_pthread_mutex_unlock((oe_pthread_mutex_t*)m);
}
