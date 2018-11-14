// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#define PTHREAD_MUTEX_INITIALIZER ELIBC_PTHREAD_MUTEX_INITIALIZER
#define PTHREAD_RWLOCK_INITIALIZER ELIBC_PTHREAD_RWLOCK_INITIALIZER
#define PTHREAD_COND_INITIALIZER ELIBC_PTHREAD_COND_INITIALIZER
#define PTHREAD_ONCE_INIT ELIBC_PTHREAD_ONCE_INIT

typedef elibc_pthread_t pthread_t;

typedef elibc_pthread_once_t pthread_once_t;

typedef elibc_pthread_spinlock_t pthread_spinlock_t;

typedef elibc_pthread_key_t pthread_key_t;

typedef elibc_pthread_attr_t pthread_attr_t;

typedef elibc_pthread_mutexattr_t pthread_mutexattr_t;

typedef elibc_pthread_mutex_t pthread_mutex_t;

typedef elibc_pthread_condattr_t pthread_condattr_t;

typedef elibc_pthread_cond_t pthread_cond_t;

typedef elibc_pthread_rwlockattr_t pthread_rwlockattr_t;

typedef elibc_pthread_rwlock_t pthread_rwlock_t;

ELIBC_INLINE
pthread_t pthread_self()
{
    return (pthread_t)elibc_pthread_self();
}

ELIBC_INLINE
int pthread_equal(pthread_t thread1, pthread_t thread2)
{
    return elibc_pthread_equal(
        (elibc_pthread_t)thread1, (elibc_pthread_t)thread2);
}

ELIBC_INLINE
int pthread_create(
    pthread_t* thread,
    const pthread_attr_t* attr,
    void* (*start_routine)(void*),
    void* arg)
{
    return elibc_pthread_create(
        (elibc_pthread_t*)thread,
        (const elibc_pthread_attr_t*)attr,
        start_routine,
        arg);
}

ELIBC_INLINE
int pthread_join(pthread_t thread, void** retval)
{
    return elibc_pthread_join((elibc_pthread_t)thread, retval);
}

ELIBC_INLINE
int pthread_detach(pthread_t thread)
{
    return elibc_pthread_detach((elibc_pthread_t)thread);
}

ELIBC_INLINE
int pthread_once(pthread_once_t* once, void (*func)(void))
{
    return elibc_pthread_once((elibc_pthread_once_t*)once, func);
}

ELIBC_INLINE
int pthread_spin_init(pthread_spinlock_t* spinlock, int pshared)
{
    return elibc_pthread_spin_init(
        (elibc_pthread_spinlock_t*)spinlock, pshared);
}

ELIBC_INLINE
int pthread_spin_lock(pthread_spinlock_t* spinlock)
{
    return elibc_pthread_spin_lock((elibc_pthread_spinlock_t*)spinlock);
}

ELIBC_INLINE
int pthread_spin_unlock(pthread_spinlock_t* spinlock)
{
    return elibc_pthread_spin_unlock((elibc_pthread_spinlock_t*)spinlock);
}

ELIBC_INLINE
int pthread_spin_destroy(pthread_spinlock_t* spinlock)
{
    return elibc_pthread_spin_destroy((elibc_pthread_spinlock_t*)spinlock);
}

ELIBC_INLINE
int pthread_mutexattr_init(pthread_mutexattr_t* attr)
{
    return elibc_pthread_mutexattr_init((elibc_pthread_mutexattr_t*)attr);
}

ELIBC_INLINE
int pthread_mutexattr_settype(pthread_mutexattr_t* attr, int type)
{
    return elibc_pthread_mutexattr_settype(
        (elibc_pthread_mutexattr_t*)attr, type);
}

ELIBC_INLINE
int pthread_mutexattr_destroy(pthread_mutexattr_t* attr)
{
    return elibc_pthread_mutexattr_destroy(
        (elibc_pthread_mutexattr_t*)attr);
}

ELIBC_INLINE
int pthread_mutex_init(pthread_mutex_t* m, const pthread_mutexattr_t* attr)
{
    return elibc_pthread_mutex_init(
        (elibc_pthread_mutex_t*)m, (const elibc_pthread_mutexattr_t*)attr);
}

ELIBC_INLINE
int pthread_mutex_lock(pthread_mutex_t* m)
{
    return elibc_pthread_mutex_lock((elibc_pthread_mutex_t*)m);
}

ELIBC_INLINE
int pthread_mutex_trylock(pthread_mutex_t* m)
{
    return elibc_pthread_mutex_trylock((elibc_pthread_mutex_t*)m);
}

ELIBC_INLINE
int pthread_mutex_unlock(pthread_mutex_t* m)
{
    return elibc_pthread_mutex_unlock((elibc_pthread_mutex_t*)m);
}

ELIBC_INLINE
int pthread_mutex_destroy(pthread_mutex_t* m)
{
    return elibc_pthread_mutex_destroy((elibc_pthread_mutex_t*)m);
}

ELIBC_INLINE
int pthread_rwlock_init(
    pthread_rwlock_t* rwlock,
    const pthread_rwlockattr_t* attr)
{
    return elibc_pthread_rwlock_init(
        (elibc_pthread_rwlock_t*)rwlock, (elibc_pthread_rwlockattr_t*)attr);
}

ELIBC_INLINE
int pthread_rwlock_rdlock(pthread_rwlock_t* rwlock)
{
    return elibc_pthread_rwlock_rdlock((elibc_pthread_rwlock_t*)rwlock);
}

ELIBC_INLINE
int pthread_rwlock_wrlock(pthread_rwlock_t* rwlock)
{
    return elibc_pthread_rwlock_wrlock((elibc_pthread_rwlock_t*)rwlock);
}

ELIBC_INLINE
int pthread_rwlock_unlock(pthread_rwlock_t* rwlock)
{
    return elibc_pthread_rwlock_unlock((elibc_pthread_rwlock_t*)rwlock);
}

ELIBC_INLINE
int pthread_rwlock_destroy(pthread_rwlock_t* rwlock)
{
    return elibc_pthread_rwlock_destroy((elibc_pthread_rwlock_t*)rwlock);
}

ELIBC_INLINE
int pthread_cond_init(pthread_cond_t* cond, const pthread_condattr_t* attr)
{
    return elibc_pthread_cond_init(
        (elibc_pthread_cond_t*)cond, (const elibc_pthread_condattr_t*)attr);
}

ELIBC_INLINE
int pthread_cond_wait(pthread_cond_t* cond, pthread_mutex_t* mutex)
{
    return elibc_pthread_cond_wait(
        (elibc_pthread_cond_t*)cond, (elibc_pthread_mutex_t*)mutex);
}

ELIBC_INLINE
int pthread_cond_timedwait(
    pthread_cond_t* cond,
    pthread_mutex_t* mutex,
    const struct timespec* ts)
{
    return elibc_pthread_cond_timedwait(
        (elibc_pthread_cond_t*)cond,
        (elibc_pthread_mutex_t*)mutex,
        (const struct elibc_timespec*)ts);
}

ELIBC_INLINE
int pthread_cond_signal(pthread_cond_t* cond)
{
    return elibc_pthread_cond_signal((elibc_pthread_cond_t*)cond);
}

ELIBC_INLINE
int pthread_cond_broadcast(pthread_cond_t* cond)
{
    return elibc_pthread_cond_broadcast((elibc_pthread_cond_t*)cond);
}

ELIBC_INLINE
int pthread_cond_destroy(pthread_cond_t* cond)
{
    return elibc_pthread_cond_destroy((elibc_pthread_cond_t*)cond);
}

ELIBC_INLINE
int pthread_key_create(pthread_key_t* key, void (*destructor)(void* value))
{
    return elibc_pthread_key_create((elibc_pthread_key_t*)key, destructor);
}

ELIBC_INLINE
int pthread_key_delete(pthread_key_t key)
{
    return elibc_pthread_key_delete((elibc_pthread_key_t)key);
}

ELIBC_INLINE
int pthread_setspecific(pthread_key_t key, const void* value)
{
    return elibc_pthread_setspecific((elibc_pthread_key_t)key, value);
}

ELIBC_INLINE
void* pthread_getspecific(pthread_key_t key)
{
    return elibc_pthread_getspecific((elibc_pthread_key_t)key);
}
