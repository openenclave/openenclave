// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_THREAD_H
#define _OE_THREAD_H

#include <pthread.h>

typedef pthread_t OE_Thread;
#define OE_ThreadSelf pthread_self

typedef pthread_mutex_t OE_Mutex;
#define OE_MUTEX_INITIALIZER PTHREAD_MUTEX_INITIALIZER
#define OE_MutexLock pthread_mutex_lock
#define OE_MutexUnlock pthread_mutex_unlock

typedef pthread_spinlock_t OE_Spinlock;
#define OE_SPINLOCK_INITIALIZER 0
#define OE_SpinLock pthread_spin_lock
#define OE_SpinUnlock pthread_spin_unlock

typedef pthread_cond_t OE_Cond;
#define OE_COND_INITIALIZER PTHREAD_COND_INITIALIZER
#define OE_CondWait pthread_cond_wait
#define OE_CondSignal pthread_cond_signal
#define OE_CondBroadcast pthread_cond_broadcast

typedef pthread_rwlock_t OE_RWLock;
#define OE_RWLOCK_INITIALIZER PTHREAD_RWLOCK_INITIALIZER
#define OE_RWLockReadLock pthread_rwlock_rdlock
#define OE_RWLockWriteLock pthread_rwlock_wrlock
#define OE_RWLockReadUnlock pthread_rwlock_unlock
#define OE_RWLockWriteUnlock pthread_rwlock_unlock

#endif /* _OE_THREAD_H */
