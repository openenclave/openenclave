// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_BITS_PTHREAD_ONCE_H
#define _OE_BITS_PTHREAD_ONCE_H

OE_INLINE
int pthread_once(pthread_once_t* once, void (*func)(void))
{
    return oe_pthread_once((oe_pthread_once_t*)once, func);
}

#endif /* _OE_BITS_PTHREAD_ONCE_H */
