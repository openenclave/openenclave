// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_BITS_PTHREAD_EQUAL_H
#define _OE_BITS_PTHREAD_EQUAL_H

OE_INLINE
int pthread_equal(pthread_t thread1, pthread_t thread2)
{
    return oe_pthread_equal((oe_pthread_t)thread1, (oe_pthread_t)thread2);
}

#endif /* _OE_BITS_PTHREAD_EQUAL_H */
