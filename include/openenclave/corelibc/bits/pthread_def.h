// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_BITS_PTHREAD_DEF_H
#define _OE_BITS_PTHREAD_DEF_H

/* Note that these types and initializers are separated out from their
 * respective functions because oelibc compiles different conflicting symbols
 * for them. Each of these could be further split out as their own compilation
 * unit, but not including all of them by default resolves the same issue.
 */
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

#endif /* _OE_BITS_PTHREAD_DEF_H */
