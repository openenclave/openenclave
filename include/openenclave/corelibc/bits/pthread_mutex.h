// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_BITS_PTHREAD_MUTEX_H
#define _OE_BITS_PTHREAD_MUTEX_H

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
int pthread_mutex_trylock(pthread_mutex_t* m)
{
    return oe_pthread_mutex_trylock((oe_pthread_mutex_t*)m);
}

#endif /* _OE_BITS_PTHREAD_MUTEX_H */
