// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <assert.h>
#include <errno.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/defs.h>
#include <openenclave/internal/enclavelibc.h>
#include <openenclave/internal/pthreadhooks.h>
#include <openenclave/internal/sgxtypes.h>
#include <openenclave/internal/thread.h>
#include <pthread.h>
#include "locale_impl.h"
#include "pthread_impl.h"

#ifdef pthread_equal
#undef pthread_equal
#endif

#ifdef pthread
#undef pthread
#endif

OE_STATIC_ASSERT(sizeof(pthread_once_t) == sizeof(oe_once_t));
OE_STATIC_ASSERT(sizeof(pthread_spinlock_t) == sizeof(oe_spinlock_t));

OE_STATIC_ASSERT(sizeof(pthread_mutex_t) >= sizeof(oe_mutex_t));
OE_STATIC_ASSERT(sizeof(pthread_cond_t) >= sizeof(oe_cond_t));
OE_STATIC_ASSERT(sizeof(pthread_rwlock_t) >= sizeof(oe_rwlock_t));

oe_result_t oe_rwlock_unlock(oe_rwlock_t* read_write_lock);

/* Map an oe_result_t to a POSIX error number */
OE_INLINE int _to_errno(oe_result_t result)
{
    switch (result)
    {
        case OE_OK:
            return 0;
        case OE_INVALID_PARAMETER:
            return EINVAL;
        case OE_BUSY:
            return EBUSY;
        case OE_NOT_OWNER:
            return EPERM;
        case OE_OUT_OF_MEMORY:
            return ENOMEM;
        default:
            return EINVAL; /* unreachable */
    }
}

/*
**==============================================================================
**
** pthread_t
**
**==============================================================================
*/

OE_STATIC_ASSERT(sizeof(struct __pthread) <= sizeof(((td_t*)NULL)->pthread));
OE_STATIC_ASSERT(sizeof(pthread_mutex_t) >= sizeof(oe_mutex_t));
OE_STATIC_ASSERT(sizeof(pthread_cond_t) >= sizeof(oe_cond_t));

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

int pthread_equal(pthread_t thread1, pthread_t thread2)
{
    return (int)oe_thread_equal((oe_thread_t)thread1, (oe_thread_t)thread2);
}

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
        assert("pthread_join(): panic" == NULL);
        return -1;
    }

    return _pthread_hooks->join(thread, retval);
}

int pthread_detach(pthread_t thread)
{
    if (!_pthread_hooks || !_pthread_hooks->detach)
    {
        assert("pthread_detach(): panic" == NULL);
        return -1;
    }

    return _pthread_hooks->detach(thread);
}

/*
**==============================================================================
**
** pthread_once_t
**
**==============================================================================
*/

int pthread_once(pthread_once_t* once, void (*func)(void))
{
    return _to_errno(oe_once((oe_once_t*)once, func));
}

/*
**==============================================================================
**
** pthread_spinlock_t
**
**==============================================================================
*/

int pthread_spin_init(pthread_spinlock_t* spinlock, int pshared)
{
    OE_UNUSED(pshared);
    return _to_errno(oe_spin_init((oe_spinlock_t*)spinlock));
}

int pthread_spin_lock(pthread_spinlock_t* spinlock)
{
    return _to_errno(oe_spin_lock((oe_spinlock_t*)spinlock));
}

int pthread_spin_unlock(pthread_spinlock_t* spinlock)
{
    return _to_errno(oe_spin_unlock((oe_spinlock_t*)spinlock));
}

int pthread_spin_destroy(pthread_spinlock_t* spinlock)
{
    return _to_errno(oe_spin_destroy((oe_spinlock_t*)spinlock));
}

/*
**==============================================================================
**
** pthread_mutex_t
**
**==============================================================================
*/

int pthread_mutexattr_init(pthread_mutexattr_t* attr)
{
    OE_UNUSED(attr);
    return 0;
}

int pthread_mutexattr_settype(pthread_mutexattr_t* attr, int type)
{
    OE_UNUSED(attr);
    OE_UNUSED(type);
    return 0;
}

int pthread_mutexattr_destroy(pthread_mutexattr_t* attr)
{
    OE_UNUSED(attr);
    return 0;
}

int pthread_mutex_init(pthread_mutex_t* m, const pthread_mutexattr_t* attr)
{
    OE_UNUSED(attr);
    return _to_errno(oe_mutex_init((oe_mutex_t*)m));
}

int pthread_mutex_lock(pthread_mutex_t* m)
{
    return _to_errno(oe_mutex_lock((oe_mutex_t*)m));
}

int pthread_mutex_trylock(pthread_mutex_t* m)
{
    return _to_errno(oe_mutex_trylock((oe_mutex_t*)m));
}

int pthread_mutex_unlock(pthread_mutex_t* m)
{
    return _to_errno(oe_mutex_unlock((oe_mutex_t*)m));
}

int pthread_mutex_destroy(pthread_mutex_t* m)
{
    return _to_errno(oe_mutex_destroy((oe_mutex_t*)m));
}

/*
**==============================================================================
**
** pthread_rwlock_t
**
**==============================================================================
*/

int pthread_rwlock_init(
    pthread_rwlock_t* rwlock,
    const pthread_rwlockattr_t* attr)
{
    OE_UNUSED(attr);
    return _to_errno(oe_rwlock_init((oe_rwlock_t*)rwlock));
}

int pthread_rwlock_rdlock(pthread_rwlock_t* rwlock)
{
    return _to_errno(oe_rwlock_rdlock((oe_rwlock_t*)rwlock));
}

int pthread_rwlock_wrlock(pthread_rwlock_t* rwlock)
{
    return _to_errno(oe_rwlock_wrlock((oe_rwlock_t*)rwlock));
}

int pthread_rwlock_unlock(pthread_rwlock_t* rwlock)
{
    return _to_errno(oe_rwlock_unlock((oe_rwlock_t*)rwlock));
}

int pthread_rwlock_destroy(pthread_rwlock_t* rwlock)
{
    return _to_errno(oe_rwlock_destroy((oe_rwlock_t*)rwlock));
}

/*
**==============================================================================
**
** pthread_cond_t
**
**==============================================================================
*/

int pthread_cond_init(pthread_cond_t* cond, const pthread_condattr_t* attr)
{
    OE_UNUSED(attr);
    return _to_errno(oe_cond_init((oe_cond_t*)cond));
}

int pthread_cond_wait(pthread_cond_t* cond, pthread_mutex_t* mutex)
{
    return _to_errno(oe_cond_wait((oe_cond_t*)cond, (oe_mutex_t*)mutex));
}

int pthread_cond_timedwait(
    pthread_cond_t* cond,
    pthread_mutex_t* mutex,
    const struct timespec* ts)
{
    OE_UNUSED(cond);
    OE_UNUSED(mutex);
    OE_UNUSED(ts);
    assert("pthread_cond_timedwait(): panic" == NULL);
    return -1;
}

int pthread_cond_signal(pthread_cond_t* cond)
{
    return _to_errno(oe_cond_signal((oe_cond_t*)cond));
}

int pthread_cond_broadcast(pthread_cond_t* cond)
{
    return _to_errno(oe_cond_broadcast((oe_cond_t*)cond));
}

int pthread_cond_destroy(pthread_cond_t* cond)
{
    return _to_errno(oe_cond_destroy((oe_cond_t*)cond));
}

/*
**==============================================================================
**
** pthread_key_t (thread specific data)
**
**==============================================================================
*/

int pthread_key_create(pthread_key_t* key, void (*destructor)(void* value))
{
    return _to_errno(oe_thread_key_create((oe_thread_key_t*)key, destructor));
}

int pthread_key_delete(pthread_key_t key)
{
    return _to_errno(oe_thread_key_delete(key));
}

int pthread_setspecific(pthread_key_t key, const void* value)
{
    return _to_errno(oe_thread_setspecific(key, value));
}

void* pthread_getspecific(pthread_key_t key)
{
    return oe_thread_getspecific(key);
}
