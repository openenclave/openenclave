// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _ELIBC_PTHREAD_H
#define _ELIBC_PTHREAD_H

#include "bits/common.h"
#include "time.h"

// clang-format off
#define ELIBC_PTHREAD_MUTEX_INITIALIZER {{0}}
#define ELIBC_PTHREAD_RWLOCK_INITIALIZER {{0}}
#define ELIBC_PTHREAD_COND_INITIALIZER {{0}}
#define ELIBC_ONCE_INIT 0
// clang-format on

typedef uint64_t elibc_pthread_t;

typedef uint32_t elibc_pthread_once_t;

typedef volatile uint32_t elibc_pthread_spinlock_t;

typedef uint32_t elibc_pthread_key_t;

typedef struct _oe_pthread_attr
{
    uint64_t __private[7];
} elibc_pthread_attr_t;

typedef struct _oe_pthread_mutexattr
{
    uint32_t __private;
} elibc_pthread_mutexattr_t;

typedef struct _oe_pthread_mutex
{
    uint64_t __private[4];
} elibc_pthread_mutex_t;

typedef struct _oe_pthread_condattr
{
    uint32_t __private;
} elibc_pthread_condattr_t;

typedef struct _oe_pthread_cond
{
    uint64_t __private[4];
} elibc_pthread_cond_t;

typedef struct _oe_pthread_rwlockattr
{
    uint32_t __private[2];
} elibc_pthread_rwlockattr_t;

typedef struct _oe_pthread_rwlock
{
    uint64_t __private[5];
} elibc_pthread_rwlock_t;

elibc_pthread_t elibc_pthread_self(void);

int elibc_pthread_equal(elibc_pthread_t thread1, elibc_pthread_t thread2);

int elibc_pthread_create(
    elibc_pthread_t* thread,
    const elibc_pthread_attr_t* attr,
    void* (*start_routine)(void*),
    void* arg);

int elibc_pthread_join(elibc_pthread_t thread, void** retval);

int elibc_pthread_detach(elibc_pthread_t thread);

int elibc_pthread_once(elibc_pthread_once_t* once, void (*func)(void));

int elibc_pthread_spin_init(
    elibc_pthread_spinlock_t* spinlock,
    int pshared);

int elibc_pthread_spin_lock(elibc_pthread_spinlock_t* spinlock);

int elibc_pthread_spin_unlock(elibc_pthread_spinlock_t* spinlock);

int elibc_pthread_spin_destroy(elibc_pthread_spinlock_t* spinlock);

int elibc_pthread_mutexattr_init(elibc_pthread_mutexattr_t* attr);

int elibc_pthread_mutexattr_settype(
    elibc_pthread_mutexattr_t* attr,
    int type);

int elibc_pthread_mutexattr_destroy(elibc_pthread_mutexattr_t* attr);

int elibc_pthread_mutex_init(
    elibc_pthread_mutex_t* m,
    const elibc_pthread_mutexattr_t* attr);

int elibc_pthread_mutex_lock(elibc_pthread_mutex_t* m);

int elibc_pthread_mutex_trylock(elibc_pthread_mutex_t* m);

int elibc_pthread_mutex_unlock(elibc_pthread_mutex_t* m);

int elibc_pthread_mutex_destroy(elibc_pthread_mutex_t* m);

int elibc_pthread_rwlock_init(
    elibc_pthread_rwlock_t* rwlock,
    const elibc_pthread_rwlockattr_t* attr);

int elibc_pthread_rwlock_rdlock(elibc_pthread_rwlock_t* rwlock);

int elibc_pthread_rwlock_wrlock(elibc_pthread_rwlock_t* rwlock);

int elibc_pthread_rwlock_unlock(elibc_pthread_rwlock_t* rwlock);

int elibc_pthread_rwlock_destroy(elibc_pthread_rwlock_t* rwlock);

int elibc_pthread_cond_init(
    elibc_pthread_cond_t* cond,
    const elibc_pthread_condattr_t* attr);

int elibc_pthread_cond_wait(
    elibc_pthread_cond_t* cond,
    elibc_pthread_mutex_t* mutex);

int elibc_pthread_cond_timedwait(
    elibc_pthread_cond_t* cond,
    elibc_pthread_mutex_t* mutex,
    const struct elibc_timespec* ts);

int elibc_pthread_cond_signal(elibc_pthread_cond_t* cond);

int elibc_pthread_cond_broadcast(elibc_pthread_cond_t* cond);

int elibc_pthread_cond_destroy(elibc_pthread_cond_t* cond);

int elibc_pthread_key_create(
    elibc_pthread_key_t* key,
    void (*destructor)(void* value));

int elibc_pthread_key_delete(elibc_pthread_key_t key);

int elibc_pthread_setspecific(elibc_pthread_key_t key, const void* value);

void* elibc_pthread_getspecific(elibc_pthread_key_t key);

#if defined(ELIBC_NEED_STDC_NAMES)

#include "bits/pthread.h"

#endif /* defined(ELIBC_NEED_STDC_NAMES) */

#endif /* _ELIBC_PTHREAD_H */
