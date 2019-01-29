// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

typedef oe_pthread_key_t pthread_key_t;

#if !defined(OE_USE_MUSL_DEFS)
typedef oe_pthread_t pthread_t;
typedef oe_pthread_once_t pthread_once_t;
typedef oe_pthread_attr_t pthread_attr_t;
typedef oe_pthread_mutex_t pthread_mutex_t;
typedef oe_pthread_mutexattr_t pthread_mutexattr_t;
typedef oe_pthread_cond_t pthread_cond_t;
typedef oe_pthread_condattr_t pthread_condattr_t;
typedef oe_pthread_rwlock_t pthread_rwlock_t;
typedef oe_pthread_rwlockattr_t pthread_rwlockattr_t;
typedef oe_pthread_spinlock_t pthread_spinlock_t;

#define PTHREAD_MUTEX_INITIALIZER OE_PTHREAD_MUTEX_INITIALIZER
#define PTHREAD_RWLOCK_INITIALIZER OE_PTHREAD_RWLOCK_INITIALIZER
#define PTHREAD_COND_INITIALIZER OE_PTHREAD_COND_INITIALIZER
#define PTHREAD_ONCE_INIT OE_PTHREAD_ONCE_INIT

OE_INLINE
pthread_t pthread_self()
{
    return (pthread_t)oe_pthread_self();
}

OE_INLINE
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

OE_INLINE
int pthread_join(pthread_t thread, void** retval)
{
    return oe_pthread_join((oe_pthread_t)thread, retval);
}

OE_INLINE
int pthread_detach(pthread_t thread)
{
    return oe_pthread_detach((oe_pthread_t)thread);
}

#endif

OE_INLINE
int pthread_equal(pthread_t thread1, pthread_t thread2)
{
    return oe_pthread_equal((oe_pthread_t)thread1, (oe_pthread_t)thread2);
}

OE_INLINE
int pthread_once(pthread_once_t* once, void (*func)(void))
{
    return oe_pthread_once((oe_pthread_once_t*)once, func);
}

OE_INLINE
int pthread_spin_init(pthread_spinlock_t* spinlock, int pshared)
{
    return oe_pthread_spin_init((oe_pthread_spinlock_t*)spinlock, pshared);
}

OE_INLINE
int pthread_spin_lock(pthread_spinlock_t* spinlock)
{
    return oe_pthread_spin_lock((oe_pthread_spinlock_t*)spinlock);
}

OE_INLINE
int pthread_spin_unlock(pthread_spinlock_t* spinlock)
{
    return oe_pthread_spin_unlock((oe_pthread_spinlock_t*)spinlock);
}

OE_INLINE
int pthread_spin_destroy(pthread_spinlock_t* spinlock)
{
    return oe_pthread_spin_destroy((oe_pthread_spinlock_t*)spinlock);
}

OE_INLINE
int pthread_mutexattr_init(pthread_mutexattr_t* attr)
{
    return oe_pthread_mutexattr_init((oe_pthread_mutexattr_t*)attr);
}

OE_INLINE
int pthread_mutexattr_settype(pthread_mutexattr_t* attr, int type)
{
    return oe_pthread_mutexattr_settype((oe_pthread_mutexattr_t*)attr, type);
}

OE_INLINE
int pthread_mutexattr_destroy(pthread_mutexattr_t* attr)
{
    return oe_pthread_mutexattr_destroy((oe_pthread_mutexattr_t*)attr);
}

OE_INLINE
int pthread_mutex_init(pthread_mutex_t* m, const pthread_mutexattr_t* attr)
{
    return oe_pthread_mutex_init(
        (oe_pthread_mutex_t*)m, (const oe_pthread_mutexattr_t*)attr);
}

OE_INLINE
int pthread_mutex_lock(pthread_mutex_t* m)
{
    return oe_pthread_mutex_lock((oe_pthread_mutex_t*)m);
}

OE_INLINE
int pthread_mutex_trylock(pthread_mutex_t* m)
{
    return oe_pthread_mutex_trylock((oe_pthread_mutex_t*)m);
}

OE_INLINE
int pthread_mutex_unlock(pthread_mutex_t* m)
{
    return oe_pthread_mutex_unlock((oe_pthread_mutex_t*)m);
}

OE_INLINE
int pthread_mutex_destroy(pthread_mutex_t* m)
{
    return oe_pthread_mutex_destroy((oe_pthread_mutex_t*)m);
}

OE_INLINE
int pthread_rwlock_init(
    pthread_rwlock_t* rwlock,
    const pthread_rwlockattr_t* attr)
{
    return oe_pthread_rwlock_init(
        (oe_pthread_rwlock_t*)rwlock, (oe_pthread_rwlockattr_t*)attr);
}

OE_INLINE
int pthread_rwlock_rdlock(pthread_rwlock_t* rwlock)
{
    return oe_pthread_rwlock_rdlock((oe_pthread_rwlock_t*)rwlock);
}

OE_INLINE
int pthread_rwlock_wrlock(pthread_rwlock_t* rwlock)
{
    return oe_pthread_rwlock_wrlock((oe_pthread_rwlock_t*)rwlock);
}

OE_INLINE
int pthread_rwlock_unlock(pthread_rwlock_t* rwlock)
{
    return oe_pthread_rwlock_unlock((oe_pthread_rwlock_t*)rwlock);
}

OE_INLINE
int pthread_rwlock_destroy(pthread_rwlock_t* rwlock)
{
    return oe_pthread_rwlock_destroy((oe_pthread_rwlock_t*)rwlock);
}

OE_INLINE
int pthread_cond_init(pthread_cond_t* cond, const pthread_condattr_t* attr)
{
    return oe_pthread_cond_init(
        (oe_pthread_cond_t*)cond, (const oe_pthread_condattr_t*)attr);
}

OE_INLINE
int pthread_cond_wait(pthread_cond_t* cond, pthread_mutex_t* mutex)
{
    return oe_pthread_cond_wait(
        (oe_pthread_cond_t*)cond, (oe_pthread_mutex_t*)mutex);
}

OE_INLINE
int pthread_cond_timedwait(
    pthread_cond_t* cond,
    pthread_mutex_t* mutex,
    const struct timespec* ts)
{
    return oe_pthread_cond_timedwait(
        (oe_pthread_cond_t*)cond,
        (oe_pthread_mutex_t*)mutex,
        (const struct oe_timespec*)ts);
}

OE_INLINE
int pthread_cond_signal(pthread_cond_t* cond)
{
    return oe_pthread_cond_signal((oe_pthread_cond_t*)cond);
}

OE_INLINE
int pthread_cond_broadcast(pthread_cond_t* cond)
{
    return oe_pthread_cond_broadcast((oe_pthread_cond_t*)cond);
}

OE_INLINE
int pthread_cond_destroy(pthread_cond_t* cond)
{
    return oe_pthread_cond_destroy((oe_pthread_cond_t*)cond);
}

OE_INLINE
int pthread_key_create(pthread_key_t* key, void (*destructor)(void* value))
{
    return oe_pthread_key_create((oe_pthread_key_t*)key, destructor);
}

OE_INLINE
int pthread_key_delete(pthread_key_t key)
{
    return oe_pthread_key_delete((oe_pthread_key_t)key);
}

OE_INLINE
int pthread_setspecific(pthread_key_t key, const void* value)
{
    return oe_pthread_setspecific((oe_pthread_key_t)key, value);
}

OE_INLINE
void* pthread_getspecific(pthread_key_t key)
{
    return oe_pthread_getspecific((oe_pthread_key_t)key);
}
