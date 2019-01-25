// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/elibc/errno.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/enclavelibc.h>
#include <openenclave/internal/thread.h>
#include <pthread.h>

elibc_pthread_t elibc_pthread_self()
{
    return (elibc_pthread_t)oe_thread_self();
}

int elibc_pthread_equal(elibc_pthread_t thread1, elibc_pthread_t thread2)
{
    return (int)oe_thread_equal((oe_thread_t)thread1, (oe_thread_t)thread2);
}

int elibc_pthread_create(
    elibc_pthread_t* thread,
    const elibc_pthread_attr_t* attr,
    void* (*start_routine)(void*),
    void* arg)
{
    OE_UNUSED(thread);
    OE_UNUSED(attr);
    OE_UNUSED(start_routine);
    OE_UNUSED(arg);
    oe_assert("elibc_pthread_create(): panic" == NULL);
    return -1;
}

int elibc_pthread_join(elibc_pthread_t thread, void** retval)
{
    OE_UNUSED(thread);
    OE_UNUSED(retval);
    oe_assert("pthread_join(): panic" == NULL);
    return -1;
}

int elibc_pthread_detach(elibc_pthread_t thread)
{
    OE_UNUSED(thread);
    oe_assert("pthread_detach(): panic" == NULL);
    return -1;
}

/* Map an oe_result_t to a POSIX error number */
ELIBC_INLINE int _to_errno(oe_result_t result)
{
    switch (result)
    {
        case OE_OK:
            return 0;
        case OE_INVALID_PARAMETER:
            return OE_EINVAL;
        case OE_BUSY:
            return OE_EBUSY;
        case OE_NOT_OWNER:
            return OE_EPERM;
        case OE_OUT_OF_MEMORY:
            return OE_ENOMEM;
        default:
            return OE_EINVAL; /* unreachable */
    }
}

/*
**==============================================================================
**
** elibc_pthread_once_t
**
**==============================================================================
*/

int elibc_pthread_once(elibc_pthread_once_t* once, void (*func)(void))
{
    return _to_errno(oe_once((oe_once_t*)once, func));
}

/*
**==============================================================================
**
** elibc_pthread_spinlock_t
**
**==============================================================================
*/

int elibc_pthread_spin_init(elibc_pthread_spinlock_t* spinlock, int pshared)
{
    OE_UNUSED(pshared);
    return _to_errno(oe_spin_init((oe_spinlock_t*)spinlock));
}

int elibc_pthread_spin_lock(elibc_pthread_spinlock_t* spinlock)
{
    return _to_errno(oe_spin_lock((oe_spinlock_t*)spinlock));
}

int elibc_pthread_spin_unlock(elibc_pthread_spinlock_t* spinlock)
{
    return _to_errno(oe_spin_unlock((oe_spinlock_t*)spinlock));
}

int elibc_pthread_spin_destroy(elibc_pthread_spinlock_t* spinlock)
{
    return _to_errno(oe_spin_destroy((oe_spinlock_t*)spinlock));
}

/*
**==============================================================================
**
** elibc_pthread_mutex_t
**
**==============================================================================
*/

int elibc_pthread_mutexattr_init(elibc_pthread_mutexattr_t* attr)
{
    OE_UNUSED(attr);
    return 0;
}

int elibc_pthread_mutexattr_settype(elibc_pthread_mutexattr_t* attr, int type)
{
    OE_UNUSED(attr);
    OE_UNUSED(type);
    return 0;
}

int elibc_pthread_mutexattr_destroy(elibc_pthread_mutexattr_t* attr)
{
    OE_UNUSED(attr);
    return 0;
}

int elibc_pthread_mutex_init(
    elibc_pthread_mutex_t* m,
    const elibc_pthread_mutexattr_t* attr)
{
    OE_UNUSED(attr);
    return _to_errno(oe_mutex_init((oe_mutex_t*)m));
}

int elibc_pthread_mutex_lock(elibc_pthread_mutex_t* m)
{
    return _to_errno(oe_mutex_lock((oe_mutex_t*)m));
}

int elibc_pthread_mutex_trylock(elibc_pthread_mutex_t* m)
{
    return _to_errno(oe_mutex_trylock((oe_mutex_t*)m));
}

int elibc_pthread_mutex_unlock(elibc_pthread_mutex_t* m)
{
    return _to_errno(oe_mutex_unlock((oe_mutex_t*)m));
}

int elibc_pthread_mutex_destroy(elibc_pthread_mutex_t* m)
{
    return _to_errno(oe_mutex_destroy((oe_mutex_t*)m));
}

/*
**==============================================================================
**
** elibc_pthread_rwlock_t
**
**==============================================================================
*/

int elibc_pthread_rwlock_init(
    elibc_pthread_rwlock_t* rwlock,
    const elibc_pthread_rwlockattr_t* attr)
{
    OE_UNUSED(attr);
    return _to_errno(oe_rwlock_init((oe_rwlock_t*)rwlock));
}

int elibc_pthread_rwlock_rdlock(elibc_pthread_rwlock_t* rwlock)
{
    return _to_errno(oe_rwlock_rdlock((oe_rwlock_t*)rwlock));
}

int elibc_pthread_rwlock_wrlock(elibc_pthread_rwlock_t* rwlock)
{
    return _to_errno(oe_rwlock_wrlock((oe_rwlock_t*)rwlock));
}

int elibc_pthread_rwlock_unlock(elibc_pthread_rwlock_t* rwlock)
{
    return _to_errno(oe_rwlock_unlock((oe_rwlock_t*)rwlock));
}

int elibc_pthread_rwlock_destroy(elibc_pthread_rwlock_t* rwlock)
{
    return _to_errno(oe_rwlock_destroy((oe_rwlock_t*)rwlock));
}

/*
**==============================================================================
**
** elibc_pthread_cond_t
**
**==============================================================================
*/

int elibc_pthread_cond_init(
    elibc_pthread_cond_t* cond,
    const elibc_pthread_condattr_t* attr)
{
    OE_UNUSED(attr);
    return _to_errno(oe_cond_init((oe_cond_t*)cond));
}

int elibc_pthread_cond_wait(
    elibc_pthread_cond_t* cond,
    elibc_pthread_mutex_t* mutex)
{
    return _to_errno(oe_cond_wait((oe_cond_t*)cond, (oe_mutex_t*)mutex));
}

int elibc_pthread_cond_timedwait(
    elibc_pthread_cond_t* cond,
    elibc_pthread_mutex_t* mutex,
    const struct elibc_timespec* ts)
{
    OE_UNUSED(cond);
    OE_UNUSED(mutex);
    OE_UNUSED(ts);
    oe_assert("pthread_cond_timedwait(): panic" == NULL);
    return -1;
}

int elibc_pthread_cond_signal(elibc_pthread_cond_t* cond)
{
    return _to_errno(oe_cond_signal((oe_cond_t*)cond));
}

int elibc_pthread_cond_broadcast(elibc_pthread_cond_t* cond)
{
    return _to_errno(oe_cond_broadcast((oe_cond_t*)cond));
}

int elibc_pthread_cond_destroy(elibc_pthread_cond_t* cond)
{
    return _to_errno(oe_cond_destroy((oe_cond_t*)cond));
}

/*
**==============================================================================
**
** elibc_pthread_key_t (thread specific data)
**
**==============================================================================
*/

int elibc_pthread_key_create(
    elibc_pthread_key_t* key,
    void (*destructor)(void* value))
{
    return _to_errno(oe_thread_key_create((oe_thread_key_t*)key, destructor));
}

int elibc_pthread_key_delete(elibc_pthread_key_t key)
{
    return _to_errno(oe_thread_key_delete((oe_thread_key_t)key));
}

int elibc_pthread_setspecific(elibc_pthread_key_t key, const void* value)
{
    return _to_errno(oe_thread_setspecific((oe_thread_key_t)key, value));
}

void* elibc_pthread_getspecific(elibc_pthread_key_t key)
{
    return oe_thread_getspecific((oe_thread_key_t)key);
}
