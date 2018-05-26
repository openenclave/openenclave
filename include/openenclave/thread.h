// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

/**
 * \file thread.h
 *
 * This file defines threading primitives used by enclaves.
 *
 */
#ifndef _OE_THREAD_H
#define _OE_THREAD_H

#include "defs.h"
#include "types.h"

OE_EXTERNC_BEGIN

typedef uint64_t OE_Thread;

/*
 * Note that all the __impl[] fields in the below implementations are
 * all larger than what is actually needed. This is to account for
 * possible future expansion by evolving implementations.
 */

typedef struct _OE_ThreadAttr
{
    /* Internal private implementation */
    uint64_t __impl[7];
} OE_ThreadAttr;

/**
 * Returns the identifier of the current thread.
 *
 * This function returns the identifier of the calling thread. Two thread
 * identifiers can be compared for the equality by OE_ThreadEqual().
 *
 * @returns Returns the thread identifier of the calling thread.
 *
 */
OE_Thread OE_ThreadSelf(void);

/**
 * Checks two thread identifiers for equality.
 *
 * This function checks whether two thread identifiers refer to the same
 * thread. Thread identifiers are obtained by calling OE_ThreadSelf().
 *
 * @param thread1 A thread identifier obtained with OE_ThreadSelf().
 * @param thread2 A thread identifier obtained with OE_ThreadSelf().
 *
 * @returns Returns non-zero if the thread identifiers are equal.
 *
 */
int OE_ThreadEqual(OE_Thread thread1, OE_Thread thread2);

typedef unsigned int OE_OnceType;

#define OE_ONCE_INITIALIZER 0

/**
 * Calls the given function exactly once.
 *
 * This function calls the function given by the **func** parameter exactly
 * one time for the given **once** parameter, no matter how many times
 * OE_Once() is called. OE_Once() may be called safely from different threads
 * and is typically used as a thread-safe mechanism for performing one-time
 * initialization, as in the example below.
 *
 *     static OE_OnceType _once = OE_ONCE_INITIALIZER;
 *
 *     static void _Initialize(void)
 *     {
 *         // Perform one time initialization here!
 *     }
 *
 *     ...
 *
 *     OE_Once(&_once, _Initialize);
 *
 * The **_Initialize** function is called by the first thread to call OE_Once()
 * for the *_once* variable.
 *
 * @param once The variable used to synchronize one-time call to **func**.
 *
 * @return Returns zero on success.
 *
 */
int OE_Once(OE_OnceType* once, void (*func)(void));

#define OE_SPINLOCK_INITIALIZER 0

typedef volatile unsigned int OE_Spinlock;

/**
 * Initializes a spin lock.
 *
 * This function initializes a spin lock. Spin locks can also be initialized
 * statically as follows.
 *
 *     static OE_Spinlock _spinlock = OE_SPINLOCK_INITIALIZER;
 *
 * Once initialized, threads may use a spin lock to synchronize access to
 * data. See OE_SpinLock() and OE_SpinUnlock().
 *
 * @param spinlock Initialize the given spin lock.
 *
 * @returns Return zero if successful
 *
 */
int OE_SpinInit(OE_Spinlock* spinlock);

/**
 * Acquire a lock on a spin lock.
 *
 * A thread calls this function to acquire a lock on a spin lock. If
 * another thread has already acquired a lock, the calling thread spins
 * until the lock is available. If more than one thread is waiting on the
 * spin lock, the selection of the next thread to obtain the lock is arbitrary.
 *
 * @param spinlock Lock this spin lock.
 *
 * @return Return zero if successful
 *
 */
int OE_SpinLock(OE_Spinlock* spinlock);

/**
 * Release the lock on a spin lock.
 *
 * A thread calls this function to release a lock on a spin lock.
 *
 * @param spinlock Unlock this spin lock.
 *
 * @return Return zero if successful
 *
 */
int OE_SpinUnlock(OE_Spinlock* spinlock);

/**
 * Destroy a spin lock.
 *
 * This function destroys a spin lock.
 *
 * @param spinlock Destroy this spin lock.
 *
 * @return Return zero if successful
 *
 */
int OE_SpinDestroy(OE_Spinlock* spinlock);

#define OE_MUTEX_INITIALIZER \
    {                        \
        {                    \
            0                \
        }                    \
    }

/* Definition of a mutex */
typedef struct _OE_Mutex
{
    /* Internal private implementation */
    uint64_t __impl[4];
} OE_Mutex;

/**
 * Initialize a mutex.
 *
 * This function initializes a mutex. All mutexes are recursive. Once
 * initialized, multiple threads can use this mutex to synchronize access
 * to data. See OE_MutexLock() and OE_MutexUnlock().
 *
 * @param mutex Initialize this mutex.
 *
 * @return Return zero on success.
 *
 */
int OE_MutexInit(OE_Mutex* mutex);

/**
 * Acquires a lock on a mutex.
 *
 * This function acquires a lock on a mutex.
 *
 * For enclaves, OE_MutexLock() performs an OCALL to wait for the mutex to
 * be signaled.
 *
 * @param mutex Acquire a lock on this mutex.
 *
 * @return Returns zero on success.
 *
 */
int OE_MutexLock(OE_Mutex* mutex);

/**
 * Tries to acquire a lock on a mutex.
 *
 * This function attempts to acquire a lock on the given mutex if it is
 * available. If the mutex is unavailable, the function returns immediately.
 * Unlike OE_MutexLock(), this function never performs an OCALL.
 *
 * @param mutex Acquire a lock on this mutex.
 *
 * @return Returns zero if the lock was obtained and non-zero if not.
 *
 */
int OE_MutexTryLock(OE_Mutex* mutex);

/**
 * Releases a mutex.
 *
 * This function releases the lock on a mutex obtained with either
 * OE_MutexLock() or OE_MutexTryLock().
 *
 * In enclaves, this function performs an OCALL, where it wakes the next
 * thread waiting on a mutex.
 *
 * @param mutex Release the lock on this mutex.
 *
 * @return Returns zero on success.
 *
 */
int OE_MutexUnlock(OE_Mutex* mutex);

/**
 * Destroys a mutex.
 *
 * This function destroys a mutex that was initialized with OE_MutexInit().
 *
 * @param Destroy this mutex.
 *
 * @return Returns zero on success.
 *
 */
int OE_MutexDestroy(OE_Mutex* mutex);

#define OE_COND_INITIALIZER \
    {                       \
        {                   \
            0               \
        }                   \
    }

/* Condition variable representation */
typedef struct _OE_Cond
{
    /* Internal private implementation */
    uint64_t __impl[4];
} OE_Cond;

/**
 * Initializes a condition variable.
 *
 * This function initializes a condition variable. Condition variables can
 * also be initialized statically as follows.
 *
 *     OE_Cond cond = OE_COND_INITIALIZER;
 *
 * Condition variables allow threads to wait on an event using a first-come
 * first-served (FCFS) policy.
 *
 * @param cond Initialize this condition variable.
 *
 * @return Returns zero on success.
 *
 */
int OE_CondInit(OE_Cond* cond);

/**
 * Waits on a condition variable.
 *
 * A thread calls this function to wait on a condition variable. If the
 * condition variable is available, OE_CondWait() returns immediately.
 * Otherwise, the thread is placed on a first-come first-served (FCFS) queue
 * where it waits to be signaled. The **mutex** parameter is used to
 * synchronize access to the condition variable. The caller locks this mutex
 * before calling OE_CondWait(), which places the thread on the waiting queue
 * and unlocks the mutex. When the thread is signaled by OE_CondSignal(), the
 * waiting thread acquires the mutex and returns.
 *
 * In enclaves, this function performs an OCALL, where the thread waits to be
 * signaled.
 *
 * @param cond Wait on this condition variable.
 * @param mutex This mutex must be locked by the caller.
 *
 * @return Returns zero on success.
 *
 */
int OE_CondWait(OE_Cond* cond, OE_Mutex* mutex);

/**
 * Signal a thread waiting on a condition variable.
 *
 * A thread calls this function to signal the next thread waiting on the
 * given condition variable. Waiting threads call OE_CondWait() which places
 * them on on a first-come first-served (FCFS) queue, where they wait to
 * be signaled. OE_CondSignal() wakes up the thread at the front of queue,
 * causing it to return from OE_CondWait().
 *
 * In enclaves, this function performs an OCALL, where it wakes the next
 * waiting thread.
 *
 * @param cond Signal this condition variable.
 *
 * @return Returns zero on success.
 *
 */
int OE_CondSignal(OE_Cond* cond);

/**
 * Signals all threads waiting on a condition variable.
 *
 * A thread calls this function to signal all threads waiting on the
 * given condition variable. Waiting threads call OE_CondWait(), which places
 * them on a first-come first-served (FCFS) queue, where they wait to be
 * signaled. OE_CondBroadcast() wakes up all threads on the queue, causing
 * them to return from OE_CondWait(). In enclaves, this function performs
 * an OCALL, where it wakes all waiting threads.
 *
 * @param cond The condition variable to be signaled.
 *
 * @return Returns zero on success.
 *
 */
int OE_CondBroadcast(OE_Cond* cond);

/**
 * Destroys a condition variable.
 *
 * This function destroys the given condition variable.
 *
 * @param cond Destroy this condition variable.
 *
 * @return Returns zero on success.
 *
 */
int OE_CondDestroy(OE_Cond* cond);

#define OE_RWLOCK_INITIALIZER \
    {                         \
        {                     \
            0                 \
        }                     \
    }

/* Readers-writer lock representation */
typedef struct _OE_RWLock
{
    /* Internal private implementation. */
    uint64_t __impl[5];
} OE_RWLock;

/**
 * Initializes a readers-writer lock.
 *
 * OE_RWLockInit initializes the lock to an unlocked state.
 * Readers-writer locks can also be initialized statically as follows.
 *
 *     OE_RWLock rwLock = OE_RWLOCK_INITIALIZER;
 *
 * Undefined behavior:
 *    1. Results of using an un-initialized r/w lock are undefined.
 *    2. Results of using a copy of a r/w lock are undefined.
 *    3. Results of re-initializing an initialized r/w lock are undefined.
 *
 * @param rwLock Initialize this readers-writer variable.
 *
 * @return Returns zero on success.
 *
 */
int OE_RWLockInit(OE_RWLock* rwLock);

/**
 * Acquires a read lock on a readers-writer lock.
 *
 * Behavior:
 *    1. The lock is acquired if no writer thread currently owns the lock.
 *    2. If the lock is currently locked for writing, OE_RWLockReadLock blocks
 *       until the writer releases the lock.
 *    3. Multiple reader threads can concurrently lock a r/w lock.
 *    4. Recursive locking. The same thread can lock a r/w lock multiple times.
 *       To release the lock, the thread must make same number of
 *       OE_RWLockReadUnlock calls.
 *    5. A deadlock will occur if the writer thread that currently owns the lock
 *       makes a OE_RWLockReadLock call.
 *    6. There is no limit to the number of readers that can acquire
 *       the lock simultaneously.
 *    7. No scheduling guarantee is provided in regards to which threads acquire
 *       the lock in presence of contention.
 *
 * Undefined behavior:
 *    1. Results of using an un-initialized or destroyed r/w lock are undefined.
 *
 * @param rwLock Acquire a read lock on this readers-writer lock.
 *
 * @return Returns zero on success.
 *
 */
int OE_RWLockReadLock(OE_RWLock* rwLock);

/**
 * Tries to acquire a read lock on a readers-writer lock.
 *
 * Behavior:
 *    1. If the lock is currently not held by a writer, the lock is acquired
 *       and returns 0.
 *    2. If the lock is currently held by a writer, the function immediately
 *       returns -1.
 *
 * Undefined behavior:
 *    1. Results of using an un-initialized or destroyed r/w lock are undefined.
 *
 * @param rwLock Acquire a read lock on this readers-writer lock.
 *
 * @return Returns zero if the lock was obtained and non-zero if not.
 *
 */
int OE_RWLockTryReadLock(OE_RWLock* rwLock);

/**
 * Releases a read lock on a readers-writer lock.
 *
 * This function releases the read lock on a readers-writer lock obtained with
 * either OE_RWLockReadLock() or OE_RWLockTryReadLock().
 *
 * Behavior:
 *    1. To release a lock, a reader thread must make the same number of
 *       OE_RWLockReadUnlock as the number of
 *       OE_RWLockReadLock/OE_RWLockTryReadLock calls.
 *    2. When all the readers have released the lock, the r/w lock goes into
 *       unlocked state and can then be acquired by writer or reader threads.
 *    3. No guarantee is provided in regards to whether a waiting writer thread
 *       or reader threads will (re)acquire the lock.
 *
 * Undefined behavior:
 *    1. Results of a OE_RWLockReadUnlock call by a thread that currently does
 *       not have a read-lock on the r/w lock are undefined.
 *
 * @param rwLock Release the read lock on this readers-writer lock.
 *
 * @return Returns zero on success.
 *
 */
int OE_RWLockReadUnlock(OE_RWLock* rwLock);

/**
 * Acquires a write lock on a readers-writer lock.
 *
 * Behavior:
 *    1. If the r/w lock is in an unlocked state, the OE_RWLockReadUnlock
 *       is successful and returns 0.
 *    2. If the r/w lock is currently held by reader threads or by another
 *       writer thread, the OE_RWLockReadUnlock call blocks until the lock is
 *       available for locking.
 *    3. No guarantee is provided in regards to whether a waiting writer thread
 *       or reader threads will (re)acquire the lock.
 *    4. OE_RWLockReadUnlock will deadlock if called by a thread that currently
 *       owns the lock for reading.
 *    5. OE_RWLockReadUnlock will deadlock if called by a thread that currently
 *       owns the lock for writing. That is, recursive-locking by writers will
 *       cause deadlocks.
 *
 * Undefined behavior:
 *    1. Results of using an un-initialized or destroyed r/w lock are undefined.
 *
 *
 * @param rwLock Acquire a write lock on this readers-writer lock.
 *
 * @return Returns zero on success.
 *
 */
int OE_RWLockWriteLock(OE_RWLock* rwLock);

/**
 * Tries to acquire a write lock on a readers-writer lock.
 *
 * Behavior:
 *    1. If the r/w lock is currently not held by readers or by another writer,
 *       the r/w lock is acquired and returns 0.
 *    2. If the lock is currently locked, the function immediately returns -1.
 *
 * Undefined behavior:
 *    1. Results of using an un-initialized or destroyed r/w lock are undefined.
 *
 * @param rwLock Acquire a write lock on this readers-writer lock.
 *
 * @return Returns zero if the lock was obtained and non-zero if not.
 *
 */
int OE_RWLockTryWriteLock(OE_RWLock* rwLock);

/**
 * Releases a write lock on a readers-writer lock.
 *
 * This function releases the write lock on a readers-writer lock obtained with
 * either OE_RWLockWriteLock() or OE_RWLockTryWriteLock().
 *
 * Behavior:
 *    1. To lock goes into unlocked state and can then be acquired by
 *       reader or writer threads.
 *    2. No guarantee is provided in regards to whether a waiting reader threads
 *       or writer thread will (re)acquire the lock.
 *
 * Undefined behavior:
 *    1. Results of a OE_RWLockTryWriteLock call by a thread that currently does
 *       not have a write-lock on the r/w lock are undefined.
 *
 * @param rwLock Release the write lock on this readers-writer lock.
 *
 * @return Returns zero on success.
 *
 */
int OE_RWLockWriteUnlock(OE_RWLock* rwLock);

/**
 * Destroys a readers-writer lock.
 *
 * This function destroys a readers-writer lock and releases any resources used
 * by the lock. The lock must be in an unlocked state.
 *
 * Undefined behavior:
 *    1. Results of using the r/w lock after it is destroyed are undefined.
 *    2. Results of using the r/w lock during its destruction are undefined.
 *    3. Results of destroying a locked r/w lock are undefined.
 *    4. Results of destroying an uninitialized r/w lock are undefined.
 *
 * @param Destroy this readers-writer lock.
 *
 * @return Returns zero on success.
 *
 */
int OE_RWLockDestroy(OE_RWLock* rwLock);

#define OE_THREADKEY_INITIALIZER 0

typedef unsigned int OE_ThreadKey;

/**
 * Create a key for accessing thread-specific data.
 *
 * This function allocates a thread-specific data (TSD) entry and initializes
 * a key for accessing it. The function given by the **destructor** parameter
 * is called when the key is deleted by OE_ThreadKeyDelete().
 *
 * @param key Set this key to refer to the newly allocated TSD entry.
 * @param destructor If non-null, call this function from OE_ThreadKeyDelete().
 *
 * @return Returns zero on success.
 *
 */
int OE_ThreadKeyCreate(OE_ThreadKey* key, void (*destructor)(void* value));

/**
 * Delete a key for accessing thread-specific data.
 *
 * This function deletes the thread-specific data (TSD) entry associated with
 * the given key, calling the function given by the **destructor** parameter
 * initially passed to OE_ThreadKeyCreate().
 *
 * @param key Delete the TSD entry associated with this key.
 *
 * @return Returns zero on success.
 *
 */
int OE_ThreadKeyDelete(OE_ThreadKey key);

/**
 * Sets the value of a thread-specific data entry.
 *
 * This function sets the value of a thread-specific data (TSD) entry
 * associated with the given key.
 *
 * @param key Set the TSD entry associated with this key.
 * @param value Set the TSD entry to this value.
 *
 * @return Returns zero on success.
 *
 */
int OE_ThreadSetSpecific(OE_ThreadKey key, const void* value);

/**
 * Gets the value of a thread-specific data entry.
 *
 * This function retrieves the value of a thread-specific data (TSD) entry
 * associated with the given key.
 *
 * @param key Get the TSD entry value associated with this key.
 *
 * @return Returns the TSD value.
 *
 */
void* OE_ThreadGetSpecific(OE_ThreadKey key);

OE_EXTERNC_END

#endif /* _OE_THREAD_H */
