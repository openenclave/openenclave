// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// Intentionally using the same guard as the internal thread.h as we
// want the pthread_enc test to be routed to the pthread* libc calls.
// Include this first to ensure that the internal/thread.h will not be
// included.
#ifndef _OE_INCLUDE_THREAD_H
#define _OE_INCLUDE_THREAD_H

#include <pthread.h>

/* Unlike OE threads, pthreads are not recursive by default */
static __inline pthread_mutex_t __mutex_initializer_recursive()
{
    pthread_mutex_t m;
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&m, &attr);
    return m;
}

typedef pthread_t oe_thread_t;
#define oe_thread_self pthread_self

typedef pthread_mutex_t oe_mutex_t;
#define OE_MUTEX_INITIALIZER __mutex_initializer_recursive()
#define oe_mutex_lock pthread_mutex_lock
#define oe_mutex_unlock pthread_mutex_unlock

typedef pthread_spinlock_t oe_spinlock_t;
#define OE_SPINLOCK_INITIALIZER 0
#define oe_spin_lock pthread_spin_lock
#define oe_spin_unlock pthread_spin_unlock

typedef pthread_cond_t oe_cond_t;
#define OE_COND_INITIALIZER PTHREAD_COND_INITIALIZER
#define oe_cond_wait pthread_cond_wait
#define oe_cond_signal pthread_cond_signal
#define oe_cond_broadcast pthread_cond_broadcast

typedef pthread_rwlock_t oe_rwlock_t;
#define OE_RWLOCK_INITIALIZER PTHREAD_RWLOCK_INITIALIZER
#define oe_rwlock_rdlock pthread_rwlock_rdlock
#define oe_rwlock_wrlock pthread_rwlock_wrlock
#define oe_rwlock_unlock pthread_rwlock_unlock

#endif /* _OE_INCLUDE_THREAD_H */
