// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_INCLUDE_THREAD_H
#define _OE_INCLUDE_THREAD_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>

typedef uint64_t oe_thread_t;

#ifdef OE_BUILD_ENCLAVE
OE_EXTERNC_BEGIN

/*
 * Note that all the __impl[] fields in the below implementations are
 * all larger than what is actually needed. This is to account for
 * possible future expansion by evolving implementations.
 */

/**
 * Thread Attribute
 */
typedef struct _oe_thread_attr
{
    uint64_t __impl[7]; /**< Internal private implementation */
} oe_thread_attr_t;

/**
 * Return the identifier of the current thread.
 *
 * This function returns the identifier of the calling thread. Two thread
 * identifiers can be compared for the equality by oe_thread_equal().
 *
 * @returns Returns the thread identifier of the calling thread.
 *
 */
oe_thread_t oe_thread_self(void);

/**
 * Check two thread identifiers for equality.
 *
 * This function checks whether two thread identifiers refer to the same
 * thread. Thread identifiers are obtained by calling oe_thread_self().
 *
 * @param thread1 A thread identifier obtained with oe_thread_self().
 * @param thread2 A thread identifier obtained with oe_thread_self().
 *
 * @returns Returns true if the thread identifiers are equal.
 *
 */
bool oe_thread_equal(oe_thread_t thread1, oe_thread_t thread2);

typedef uint32_t oe_once_t;

/**
 * @cond DEV
 */
#define OE_ONCE_INIT 0
#define OE_ONCE_INITIALIZER 0
#define OE_SPINLOCK_INITIALIZER 0
#define OE_MUTEX_INITIALIZER \
    {                        \
        {                    \
            0                \
        }                    \
    }

#define OE_COND_INITIALIZER \
    {                       \
        {                   \
            0               \
        }                   \
    }

#define OE_RWLOCK_INITIALIZER \
    {                         \
        {                     \
            0                 \
        }                     \
    }

#define OE_THREADKEY_INITIALIZER 0

/**
 * @endcond
 */

/**
 * Call the given function exactly once.
 *
 * This function calls the function given by the **func** parameter exactly
 * one time for the given **once** parameter, no matter how many times
 * oe_once() is called. oe_once() may be called safely from different threads
 * and is typically used as a thread-safe mechanism for performing one-time
 * initialization, as in the example below.
 *
 *     static oe_once_t _once = OE_ONCE_INIT;
 *
 *     static void _initialize(void)
 *     {
 *         // Perform one time initialization here!
 *     }
 *
 *     ...
 *
 *     oe_once(&_once, _initialize);
 *
 * The **_initialize** function is called by the first thread to call oe_once()
 * for the *_once* variable.
 *
 * @param once The variable used to synchronize one-time call to **func**.
 *
 * @return OE_OK the operation was successful
 * @return OE_INVALID_PARAMETER one or more parameters is invalid
 *
 */
oe_result_t oe_once(oe_once_t* once, void (*func)(void));

#define OE_SPINLOCK_INITIALIZER 0

typedef volatile uint32_t oe_spinlock_t;

/**
 * Initialize a spin lock.
 *
 * This function initializes a spin lock. Spin locks can also be initialized
 * statically as follows.
 *
 *     static oe_spinlock_t _spinlock = OE_SPINLOCK_INITIALIZER;
 *
 * Once initialized, threads may use a spin lock to synchronize access to
 * data. See oe_spin_lock() and oe_spin_unlock().
 *
 * @param spinlock Initialize the given spin lock.
 *
 * @return OE_OK the operation was successful
 * @return OE_INVALID_PARAMETER one or more parameters is invalid
 *
 */
oe_result_t oe_spin_init(oe_spinlock_t* spinlock);

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
 * @return OE_OK the operation was successful
 * @return OE_INVALID_PARAMETER one or more parameters is invalid
 *
 */
oe_result_t oe_spin_lock(oe_spinlock_t* spinlock);

/**
 * Release the lock on a spin lock.
 *
 * A thread calls this function to release a lock on a spin lock.
 *
 * @param spinlock Unlock this spin lock.
 *
 * @return OE_OK the operation was successful
 * @return OE_INVALID_PARAMETER one or more parameters is invalid
 *
 */
oe_result_t oe_spin_unlock(oe_spinlock_t* spinlock);

/**
 * Destroy a spin lock.
 *
 * This function destroys a spin lock.
 *
 * @param spinlock Destroy this spin lock.
 *
 * @return OE_OK the operation was successful
 * @return OE_INVALID_PARAMETER one or more parameters is invalid
 *
 */
oe_result_t oe_spin_destroy(oe_spinlock_t* spinlock);

/**
 * Definition of a mutex.
 */
typedef struct _oe_mutex
{
    uint64_t __impl[4]; /**< Internal private implementation */
} oe_mutex_t;

/**
 * Initialize a mutex.
 *
 * This function initializes a mutex. All mutexes are recursive. Once
 * initialized, multiple threads can use this mutex to synchronize access
 * to data. See oe_mutex_lock() and oe_mutex_unlock().
 *
 * @param mutex Initialize this mutex.
 *
 * @return OE_OK the operation was successful
 * @return OE_INVALID_PARAMETER one or more parameters is invalid
 *
 */
oe_result_t oe_mutex_init(oe_mutex_t* mutex);

/**
 * Acquire a lock on a mutex.
 *
 * This function acquires a lock on a mutex.
 *
 * For enclaves, oe_mutex_lock() performs an OCALL to wait for the mutex to
 * be signaled.
 *
 * @param mutex Acquire a lock on this mutex.
 *
 * @return OE_OK the operation was successful
 * @return OE_INVALID_PARAMETER one or more parameters is invalid
 *
 */
oe_result_t oe_mutex_lock(oe_mutex_t* mutex);

/**
 * Try to acquire a lock on a mutex.
 *
 * This function attempts to acquire a lock on the given mutex if it is
 * available. If the mutex is unavailable, the function returns immediately.
 * Unlike oe_mutex_lock(), this function never performs an OCALL.
 *
 * @param mutex Acquire a lock on this mutex.
 *
 * @return OE_OK the operation was successful
 * @return OE_INVALID_PARAMETER one or more parameters is invalid
 * @return OE_BUSY the lock was busy
 *
 */
oe_result_t oe_mutex_trylock(oe_mutex_t* mutex);

/**
 * Release a mutex.
 *
 * This function releases the lock on a mutex obtained with either
 * oe_mutex_lock() or oe_mutex_trylock().
 *
 * In enclaves, this function performs an OCALL, where it wakes the next
 * thread waiting on a mutex.
 *
 * @param mutex Release the lock on this mutex.
 *
 * @return OE_OK the operation was successful
 * @return OE_INVALID_PARAMETER one or more parameters is invalid
 * @return OE_NOT_OWNER the calling thread does not have the mutex locked
 *
 */
oe_result_t oe_mutex_unlock(oe_mutex_t* mutex);

/**
 * Destroy a mutex.
 *
 * This function destroys a mutex that was initialized with oe_mutex_init().
 *
 * @param Destroy this mutex.
 *
 * @return OE_OK the operation was successful
 * @return OE_INVALID_PARAMETER one or more parameters is invalid
 * @return OE_BUSY threads are still waiting for this mutex
 *
 */
oe_result_t oe_mutex_destroy(oe_mutex_t* mutex);

/**
 * Condition variable representation
 */
typedef struct _oe_cond
{
    uint64_t __impl[4]; /**< Internal private implementation */
} oe_cond_t;

/**
 * Initialize a condition variable
 *
 * This function initializes a condition variable. Condition variables can
 * also be initialized statically as follows.
 *
 *     oe_cond_t cond = OE_COND_INITIALIZER;
 *
 * Condition variables allow threads to wait on an event using a first-come
 * first-served (FCFS) policy.
 *
 * @param cond Initialize this condition variable.
 *
 * @return OE_OK the operation was successful
 * @return OE_INVALID_PARAMETER one or more parameters is invalid
 *
 */
oe_result_t oe_cond_init(oe_cond_t* cond);

/**
 * Wait on a condition variable.
 *
 * A thread calls this function to wait on a condition variable. If the
 * condition variable is available, oe_cond_wait() returns immediately.
 * Otherwise, the thread is placed on a first-come first-served (FCFS) queue
 * where it waits to be signaled. The **mutex** parameter is used to
 * synchronize access to the condition variable. The caller locks this mutex
 * before calling oe_cond_wait(), which places the thread on the waiting queue
 * and unlocks the mutex. When the thread is signaled by oe_cond_signal(), the
 * waiting thread acquires the mutex and returns.
 *
 * In enclaves, this function performs an OCALL, where the thread waits to be
 * signaled.
 *
 * @param cond Wait on this condition variable.
 * @param mutex This mutex must be locked by the caller.
 *
 * @return OE_OK the operation was successful
 * @return OE_INVALID_PARAMETER one or more parameters is invalid
 * @return OE_BUSY the mutex is not locked by the calling thread.
 *
 */
oe_result_t oe_cond_wait(oe_cond_t* cond, oe_mutex_t* mutex);

/**
 * Signal a thread waiting on a condition variable.
 *
 * A thread calls this function to signal the next thread waiting on the
 * given condition variable. Waiting threads call oe_cond_wait() which places
 * them on a first-come first-served (FCFS) queue, where they wait to
 * be signaled. oe_cond_signal() wakes up the thread at the front of queue,
 * causing it to return from oe_cond_wait().
 *
 * In enclaves, this function performs an OCALL, where it wakes the next
 * waiting thread.
 *
 * @param cond Signal this condition variable.
 *
 * @return OE_OK the operation was successful
 * @return OE_INVALID_PARAMETER one or more parameters is invalid
 *
 */
oe_result_t oe_cond_signal(oe_cond_t* cond);

/**
 * Signal all threads waiting on a condition variable.
 *
 * A thread calls this function to signal all threads waiting on the
 * given condition variable. Waiting threads call oe_cond_wait(), which places
 * them on a first-come first-served (FCFS) queue, where they wait to be
 * signaled. oe_cond_broadcast() wakes up all threads on the queue, causing
 * them to return from oe_cond_wait(). In enclaves, this function performs
 * an OCALL, where it wakes all waiting threads.
 *
 * @param cond The condition variable to be signaled.
 *
 * @return OE_OK the operation was successful
 * @return OE_INVALID_PARAMETER one or more parameters is invalid
 *
 */
oe_result_t oe_cond_broadcast(oe_cond_t* cond);

/**
 * Destroy a condition variable.
 *
 * This function destroys the given condition variable.
 *
 * @param cond Destroy this condition variable.
 *
 * @return OE_OK the operation was successful
 * @return OE_INVALID_PARAMETER one or more parameters is invalid
 * @return OE_BUSY threads are still waiting on this condition
 *
 */
oe_result_t oe_cond_destroy(oe_cond_t* cond);

/**
 * Readers-writer lock representation.
 */
typedef struct _oe_rwlock
{
    uint64_t __impl[5]; /**< Internal private implementation */
} oe_rwlock_t;

/**
 * Initialize a readers-writer lock.
 *
 * oe_rwlock_init initializes the lock to an unlocked state.
 * Readers-writer locks can also be initialized statically as follows.
 *
 *     oe_rwlock_t rw_lock = OE_RWLOCK_INITIALIZER;
 *
 * Undefined behavior:
 *    1. Results of using an uninitialized r/w lock are undefined.
 *    2. Results of using a copy of a r/w lock are undefined.
 *    3. Results of re-initializing an initialized r/w lock are undefined.
 *
 * @param rw_lock Initialize this readers-writer variable.
 *
 * @return OE_OK the operation was successful
 * @return OE_INVALID_PARAMETER one or more parameters is invalid
 *
 */
oe_result_t oe_rwlock_init(oe_rwlock_t* rw_lock);

/**
 * Acquire a read lock on a readers-writer lock.
 *
 * Behavior:
 *    1. The lock is acquired if no writer thread currently owns the lock.
 *    2. If the lock is currently locked for writing, oe_rwlock_rdlock blocks
 *       until the writer releases the lock.
 *    3. Multiple reader threads can concurrently lock a r/w lock.
 *    4. Recursive locking. The same thread can lock a r/w lock multiple times.
 *       To release the lock, the thread must make same number of
 *       oe_rwlock_unlock calls.
 *    5. A deadlock will occur if the writer thread that currently owns the lock
 *       makes a oe_rwlock_rdlock call.
 *    6. There is no limit to the number of readers that can acquire
 *       the lock simultaneously.
 *    7. No scheduling guarantee is provided in regards to which threads acquire
 *       the lock in presence of contention.
 *
 * Undefined behavior:
 *    1. Results of using an uninitialized or destroyed r/w lock are undefined.
 *
 * @param rw_lock Acquire a read lock on this readers-writer lock.
 *
 * @return OE_OK the operation was successful
 * @return OE_INVALID_PARAMETER one or more parameters is invalid
 *
 */
oe_result_t oe_rwlock_rdlock(oe_rwlock_t* rw_lock);

/**
 * Try to acquire a read lock on a readers-writer lock.
 *
 * Behavior:
 *    1. If the lock is currently not held by a writer, the lock is acquired
 *       and returns OE_OK.
 *    2. If the lock is currently held by a writer, the function immediately
 *       returns OE_BUSY.
 *
 * Undefined behavior:
 *    1. Results of using an uninitialized or destroyed r/w lock are undefined.
 *
 * @param rw_lock Acquire a read lock on this readers-writer lock.
 *
 * @return OE_OK the operation was successful
 * @return OE_INVALID_PARAMETER one or more parameters is invalid
 * @return OE_BUSY the lock was busy
 *
 */
oe_result_t oe_rwlock_tryrdlock(oe_rwlock_t* rw_lock);

/**
 * Release a read lock on a readers-writer lock.
 *
 * This function releases the lock on a readers-writer lock obtained with
 * one of these:
 *     - oe_rwlock_rdlock()
 *     - oe_rwlock_tryrdlock()
 *     - oe_rwlock_trywrlock()
 *     - or oe_rwlock_trywrlock()
 *
 * Behavior:
 *    1. To release a lock, a thread must make the same number of unlock
 *       calls as the number of lock calls.
 *    2. When all the readers have released the lock, the r/w lock goes into an
 *       unlocked state and can then be acquired by writer or reader threads.
 *    3. When the writer releases the lock, the r/w lock is once again available
 *       to be locked for write.
 *    4. No guarantee is provided in regards to whether a waiting writer thread
 *       or reader threads will (re)acquire the lock.
 *
 * Undefined behavior:
 *    1. Results of a oe_rwlock_unlock call by a thread that currently does
 *       not have a lock on the r/w lock are undefined.
 *
 * @param rw_lock Release the lock on this readers-writer lock.
 *
 * @return OE_OK the operation was successful.
 * @return OE_INVALID_PARAMETER one or more parameters is invalid.
 * @return OE_NOT_OWNER the calling thread does not have this object locked.
 * @return OE_NOT_BUSY readers still exist.
 *
 */
oe_result_t oe_rwlock_unlock(oe_rwlock_t* rw_lock);

/**
 * Acquire a write lock on a readers-writer lock.
 *
 * Behavior:
 *    1. If the r/w lock is in an unlocked state, the oe_rwlock_unlock
 *       is successful and returns OE_OK.
 *    2. If the r/w lock is currently held by reader threads or by another
 *       writer thread, the oe_rwlock_unlock call blocks until the lock is
 *       available for locking.
 *    3. No guarantee is provided in regards to whether a waiting writer thread
 *       or reader threads will (re)acquire the lock.
 *    4. oe_rwlock_unlock will deadlock if called by a thread that currently
 *       owns the lock for reading.
 *    5. oe_rwlock_unlock will deadlock if called by a thread that currently
 *       owns the lock for writing. That is, recursive-locking by writers will
 *       cause deadlocks.
 *
 * Undefined behavior:
 *    1. Results of using an uninitialized or destroyed r/w lock are undefined.
 *
 *
 * @param rw_lock Acquire a write lock on this readers-writer lock.
 *
 * @return OE_OK the operation was successful
 * @return OE_INVALID_PARAMETER one or more parameters is invalid
 * @return OE_BUSY object is already locked for writing by this thread
 *
 */
oe_result_t oe_rwlock_wrlock(oe_rwlock_t* rw_lock);

/**
 * Try to acquire a write lock on a readers-writer lock.
 *
 * Behavior:
 *    1. If the r/w lock is currently not held by readers or by another writer,
 *       the r/w lock is acquired and returns OE_OK.
 *    2. If the lock is currently locked, the function immediately returns
 *       OE_BUSY.
 *
 * Undefined behavior:
 *    1. Results of using an uninitialized or destroyed r/w lock are undefined.
 *
 * @param rw_lock Acquire a write lock on this readers-writer lock.
 *
 * @return OE_OK the operation was successful
 * @return OE_INVALID_PARAMETER one or more parameters is invalid
 * @return OE_BUSY the lock was busy
 *
 */
oe_result_t oe_rwlock_trywrlock(oe_rwlock_t* rw_lock);

/**
 * Destroy a readers-writer lock.
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
 * @return OE_OK the operation was successful
 * @return OE_INVALID_PARAMETER one or more parameters is invalid
 * @return OE_BUSY threads are still waiting on this lock
 *
 */
oe_result_t oe_rwlock_destroy(oe_rwlock_t* rw_lock);

typedef uint32_t oe_thread_key_t;

/**
 * Create a key for accessing thread-specific data.
 *
 * This function allocates a thread-specific data (TSD) entry and initializes
 * a key for accessing it. The function given by the **destructor** parameter
 * is called when the key is deleted by oe_thread_key_delete().
 *
 * @param key Set this key to refer to the newly allocated TSD entry.
 * @param destructor If non-null, this function is called for each exiting
 *        thread that has a non-null thread-specific data value. An enclave
 *        thread exits when returning from the outermost ECALL.
 *
 * @return OE_OK the operation was successful
 * @return OE_INVALID_PARAMETER one or more parameters is invalid
 * @return OE_OUT_OF_MEMORY insufficient memory exists to create the key
 *
 */
oe_result_t oe_thread_key_create(
    oe_thread_key_t* key,
    void (*destructor)(void* value));

/**
 * Delete a key for accessing thread-specific data.
 *
 * This function deletes the thread-specific data (TSD) entry associated with
 * the given key.
 *
 * @param key Delete the TSD entry associated with this key.
 *
 * @return OE_OK the operation was successful
 * @return OE_INVALID_PARAMETER one or more parameters is invalid
 *
 */
oe_result_t oe_thread_key_delete(oe_thread_key_t key);

/**
 * Set the value of a thread-specific data entry.
 *
 * This function sets the value of a thread-specific data (TSD) entry
 * associated with the given key.
 *
 * @param key Set the TSD entry associated with this key.
 * @param value Set the TSD entry to this value.
 *
 * @return OE_OK the operation was successful
 * @return OE_INVALID_PARAMETER one or more parameters is invalid
 *
 */
oe_result_t oe_thread_setspecific(oe_thread_key_t key, const void* value);

/**
 * Get the value of a thread-specific data entry.
 *
 * This function retrieves the value of a thread-specific data (TSD) entry
 * associated with the given key.
 *
 * @param key Get the TSD entry value associated with this key.
 *
 * @return Returns the TSD value or null if none.
 *
 */
void* oe_thread_getspecific(oe_thread_key_t key);

OE_EXTERNC_END

#endif // OE_BUILD_ENCLAVE

#endif //_OE_INCLUDE_THREAD_H
