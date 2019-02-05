// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_BITS_PTHREAD_CREATE_H
#define _OE_BITS_PTHREAD_CREATE_H

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

#endif /* _OE_BITS_PTHREAD_CREATE_H */