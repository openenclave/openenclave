// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_BITS_PTHREAD_KEY_H
#define _OE_BITS_PTHREAD_KEY_H

typedef oe_pthread_key_t pthread_key_t;

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

#endif /* _OE_BITS_PTHREAD_KEY_H */
