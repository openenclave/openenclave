// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_BITS_PTHREAD_SPIN_H
#define _OE_BITS_PTHREAD_SPIN_H

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

#endif /* _OE_BITS_PTHREAD_SPIN_H */
