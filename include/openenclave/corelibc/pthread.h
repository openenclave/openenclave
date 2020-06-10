// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_PTHREAD_H
#define _OE_PTHREAD_H

#include <openenclave/bits/time.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

/*
**==============================================================================
**
** OE names:
**
**==============================================================================
*/

// clang-format off
#define OE_PTHREAD_MUTEX_INITIALIZER {{0}}
#define OE_PTHREAD_RWLOCK_INITIALIZER {{0}}
#define OE_PTHREAD_COND_INITIALIZER {{0}}
#define OE_ONCE_INIT 0
// clang-format on

typedef uint64_t oe_pthread_t;

typedef uint32_t oe_pthread_once_t;

typedef volatile uint32_t oe_pthread_spinlock_t;

typedef uint32_t oe_pthread_key_t;

typedef struct _oe_pthread_attr
{
    uint64_t __private[7];
} oe_pthread_attr_t;

typedef struct _oe_pthread_mutexattr
{
    uint32_t __private;
} oe_pthread_mutexattr_t;

typedef struct _oe_pthread_mutex
{
    uint64_t __private[4];
} oe_pthread_mutex_t;

typedef struct _oe_pthread_condattr
{
    uint32_t __private;
} oe_pthread_condattr_t;

typedef struct _oe_pthread_cond
{
    uint64_t __private[4];
} oe_pthread_cond_t;

typedef struct _oe_pthread_rwlockattr
{
    uint32_t __private[2];
} oe_pthread_rwlockattr_t;

typedef struct _oe_pthread_rwlock
{
    uint64_t __private[5];
} oe_pthread_rwlock_t;

oe_pthread_t oe_pthread_self(void);

int oe_pthread_equal(oe_pthread_t thread1, oe_pthread_t thread2);

int oe_pthread_create(
    oe_pthread_t* thread,
    const oe_pthread_attr_t* attr,
    void* (*start_routine)(void*),
    void* arg);

int oe_pthread_join(oe_pthread_t thread, void** retval);

int oe_pthread_detach(oe_pthread_t thread);

int oe_pthread_once(oe_pthread_once_t* once, void (*func)(void));

int oe_pthread_spin_init(oe_pthread_spinlock_t* spinlock, int pshared);

int oe_pthread_spin_lock(oe_pthread_spinlock_t* spinlock);

int oe_pthread_spin_unlock(oe_pthread_spinlock_t* spinlock);

int oe_pthread_spin_destroy(oe_pthread_spinlock_t* spinlock);

int oe_pthread_mutexattr_init(oe_pthread_mutexattr_t* attr);

int oe_pthread_mutexattr_settype(oe_pthread_mutexattr_t* attr, int type);

int oe_pthread_mutexattr_destroy(oe_pthread_mutexattr_t* attr);

int oe_pthread_mutex_init(
    oe_pthread_mutex_t* m,
    const oe_pthread_mutexattr_t* attr);

int oe_pthread_mutex_lock(oe_pthread_mutex_t* m);

int oe_pthread_mutex_trylock(oe_pthread_mutex_t* m);

int oe_pthread_mutex_unlock(oe_pthread_mutex_t* m);

int oe_pthread_mutex_destroy(oe_pthread_mutex_t* m);

int oe_pthread_rwlock_init(
    oe_pthread_rwlock_t* rwlock,
    const oe_pthread_rwlockattr_t* attr);

int oe_pthread_rwlock_rdlock(oe_pthread_rwlock_t* rwlock);

int oe_pthread_rwlock_wrlock(oe_pthread_rwlock_t* rwlock);

int oe_pthread_rwlock_unlock(oe_pthread_rwlock_t* rwlock);

int oe_pthread_rwlock_destroy(oe_pthread_rwlock_t* rwlock);

int oe_pthread_cond_init(
    oe_pthread_cond_t* cond,
    const oe_pthread_condattr_t* attr);

int oe_pthread_cond_wait(oe_pthread_cond_t* cond, oe_pthread_mutex_t* mutex);

int oe_pthread_cond_timedwait(
    oe_pthread_cond_t* cond,
    oe_pthread_mutex_t* mutex,
    const struct oe_timespec* ts);

int oe_pthread_cond_signal(oe_pthread_cond_t* cond);

int oe_pthread_cond_broadcast(oe_pthread_cond_t* cond);

int oe_pthread_cond_destroy(oe_pthread_cond_t* cond);

int oe_pthread_key_create(
    oe_pthread_key_t* key,
    void (*destructor)(void* value));

int oe_pthread_key_delete(oe_pthread_key_t key);

int oe_pthread_setspecific(oe_pthread_key_t key, const void* value);

void* oe_pthread_getspecific(oe_pthread_key_t key);

/*
**==============================================================================
**
** Standard-C names:
**
**==============================================================================
*/

#if defined(OE_NEED_STDC_NAMES)

#include <openenclave/corelibc/bits/pthread_def.h>
#include <openenclave/corelibc/bits/pthread_cond.h>
#include <openenclave/corelibc/bits/pthread_create.h>
#include <openenclave/corelibc/bits/pthread_equal.h>
#include <openenclave/corelibc/bits/pthread_key.h>
#include <openenclave/corelibc/bits/pthread_mutex.h>
#include <openenclave/corelibc/bits/pthread_once.h>
#include <openenclave/corelibc/bits/pthread_rwlock.h>
#include <openenclave/corelibc/bits/pthread_spin.h>

#endif /* defined(OE_NEED_STDC_NAMES) */

OE_EXTERNC_END

#endif /* _OE_PTHREAD_H */
