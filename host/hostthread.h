// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

/**
 * \file hostthread.h
 *
 * This file defines threading primitives used by the host.
 *
 */
#ifndef _HOSTTHREAD_H
#define _HOSTTHREAD_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>
#include <openenclave/internal/thread.h>

#if __GNUC__
#include <pthread.h>
#elif _MSC_VER
#include <Windows.h>
#else
#error Unknown compiler/host. Please adapt.
#endif

OE_EXTERNC_BEGIN

#if __GNUC__

typedef pthread_once_t oe_once_type;
#define OE_H_ONCE_INITIALIZER PTHREAD_ONCE_INIT

typedef pthread_mutex_t oe_mutex;
#define OE_H_MUTEX_INITIALIZER PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP

typedef pthread_key_t oe_thread_key;

#elif _MSC_VER

typedef INIT_ONCE oe_once_type;
#define OE_H_ONCE_INITIALIZER INIT_ONCE_STATIC_INIT

typedef HANDLE oe_mutex;
#define OE_H_MUTEX_INITIALIZER INVALID_HANDLE_VALUE

typedef DWORD oe_thread_key;

#endif

/**
 * Create a platform-specific thread.
 *
 * @param func The pointer to the start routine.
 * @param arg The argument to the start routine.
 *
 * @returns Returns zero on success.
 */
int oe_thread_create(oe_thread_t* thread, void* (*func)(void*), void* arg);

/**
 * Join a platform-specific thread.
 *
 * @param thread The thread to be joined.
 *
 * @returns Returns zero on success.
 */
int oe_thread_join(oe_thread_t thread);

/**
 * Returns the identifier of the current thread.
 *
 * This function returns the identifier of the calling thread. Two thread
 * identifiers can be compared for the equality by oe_thread_equal().
 *
 * @returns Returns the thread identifier of the calling thread.
 */
oe_thread_t oe_thread_self(void);

/**
 * Checks two thread identifiers for equality.
 *
 * This function checks whether two thread identifiers refer to the same
 * thread. Thread identifiers are obtained by calling oe_thread_self().
 *
 * @param thread1 A thread identifier obtained with oe_thread_self().
 * @param thread2 A thread identifier obtained with oe_thread_self().
 *
 * @returns Returns non-zero if the thread identifiers are equal.
 */
int oe_thread_equal(oe_thread_t thread1, oe_thread_t thread2);

/**
 * Calls the given function exactly once.
 *
 * This function calls the function given by the **func** parameter exactly
 * one time for the given **once** parameter, no matter how many times
 * oe_once() is called. oe_once() may be called safely from different threads
 * and is typically used as a thread-safe mechanism for performing one-time
 * initialization, as in the example below.
 *
 *     static oe_once_type _once = OE_H_ONCE_INITIALIZER;
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
 * @return Returns zero on success.
 */
int oe_once(oe_once_type* once, void (*func)(void));

/**
 * Initialize a mutex.
 *
 * This function initializes a mutex. All mutexes are recursive. Once
 * initialized, multiple threads can use this mutex to synchronize access
 * to data. See oe_mutex_lock() and oe_mutex_unlock().
 *
 * @param mutex Initialize this mutex.
 *
 * @return Return zero on success.
 */
int oe_mutex_init(oe_mutex* Lock);

/**
 * Acquires a lock on a mutex.
 *
 * This function acquires a lock on a mutex.
 *
 * @param mutex Acquire a lock on this mutex.
 *
 * @return Returns zero on success.
 */
int oe_mutex_lock(oe_mutex* Lock);

/**
 * Tries to acquire a lock on a mutex.
 *
 * This function attempts to acquire a lock on the given mutex if it is
 * available. If the mutex is unavailable, the function returns immediately.
 * Unlike oe_mutex_lock(), this function never performs an OCALL.
 *
 * @param mutex Acquire a lock on this mutex.
 *
 * @return Returns zero if the lock was obtained and non-zero if not.
 */
int oe_mutex_trylock(oe_mutex* mutex);

/**
 * Releases a mutex.
 *
 * This function releases the lock on a mutex obtained with either
 * oe_mutex_lock() or oe_mutex_trylock().
 *
 * In enclaves, this function performs an OCALL, where it wakes the next
 * thread waiting on a mutex.
 *
 * @param mutex Release the lock on this mutex.
 *
 * @return Returns zero on success.
 */
int oe_mutex_unlock(oe_mutex* mutex);

/**
 * Destroys a mutex.
 *
 * This function destroys a mutex that was initialized with oe_mutex_init().
 *
 * @param Destroy this mutex.
 *
 * @return Returns zero on success.
 */
int oe_mutex_destroy(oe_mutex* mutex);

/**
 * Create a key for accessing thread-specific data.
 *
 * This function allocates a thread-specific data (TSD) entry and initializes
 * a key for accessing it.
 *
 * @param key Set this key to refer to the newly allocated TSD entry.
 *
 * @return Returns zero on success.
 */
int oe_thread_key_create(oe_thread_key* key);

/**
 * Delete a key for accessing thread-specific data.
 *
 * This function deletes the thread-specific data (TSD) entry associated with
 * the given key.
 *
 * @param key Delete the TSD entry associated with this key.
 *
 * @return Returns zero on success.
 */
int oe_thread_key_delete(oe_thread_key key);

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
 */
int oe_thread_setspecific(oe_thread_key key, void* value);

/**
 * Gets the value of a thread-specific data entry.
 *
 * This function retrieves the value of a thread-specific data (TSD) entry
 * associated with the given key.
 *
 * @param key Get the TSD entry value associated with this key.
 *
 * @return Returns the TSD value.
 */
void* oe_thread_getspecific(oe_thread_key key);

OE_EXTERNC_END

#endif /* _HOSTTHREAD_H */
