// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_BITS_PTHREAD_COND_H
#define _OE_BITS_PTHREAD_COND_H

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

#endif /* _OE_BITS_PTHREAD_COND_H */
