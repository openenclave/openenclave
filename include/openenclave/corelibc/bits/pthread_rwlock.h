// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_BITS_PTHREAD_RWLOCK_H
#define _OE_BITS_PTHREAD_RWLOCK_H

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

#endif /* _OE_BITS_PTHREAD_RWLOCK_H */
