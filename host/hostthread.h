/**
 * \file hostthread.h
 *
 * This file defines threading primitives used by the host.
 *
 */
#ifndef _HOSTTHREAD_H
#define _HOSTTHREAD_H

#include <openenclave/defs.h>
#include <openenclave/types.h>

#if __GNUC__
#include <pthread.h>
#elif _MSC_VER
#include <Windows.h>
#else
#error Unknown compiler/host. Please adapt.
#endif

OE_EXTERNC_BEGIN

#if __GNUC__

    typedef pthread_once_t OE_H_OnceType;
#   define OE_H_ONCE_INITIALIZER PTHREAD_ONCE_INIT

    typedef pthread_t OE_H_Thread;

    typedef pthread_mutex_t OE_H_Mutex;
#   define OE_H_MUTEX_INITIALIZER PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP

    typedef pthread_key_t OE_H_ThreadKey;

#elif _MSC_VER

    typedef INIT_ONCE OE_H_OnceType;
#   define OE_H_ONCE_INITIALIZER INIT_ONCE_STATIC_INIT

    typedef DWORD OE_H_Thread;

    typedef HANDLE OE_H_Mutex;
#   define OE_H_MUTEX_INITIALIZER INVALID_HANDLE_VALUE

    typedef DWORD OE_H_ThreadKey;

#endif

/**
 * Returns the identifier of the current thread.
 *
 * This function returns the identifier of the calling thread. Two thread
 * identifiers can be compared for the equality by OE_ThreadEqual().
 *
 * @returns Returns the thread identifier of the calling thread.
 */
OE_H_Thread OE_H_ThreadSelf(void);

/**
 * Checks two thread identifiers for equality.
 *
 * This function checks whether two thread identifiers refer to the same
 * thread. Thread identifiers are obtained by calling OE_ThreadSelf().
 *
 * @param thread1 A thread identifer obtained with OE_ThreadSelf().
 * @param thread2 A thread identifer obtained with OE_ThreadSelf().
 *
 * @returns Returns non-zero if the thread identifiers are equal.
 */
int OE_H_ThreadEqual(OE_H_Thread thread1, OE_H_Thread thread2);


/**
 * Calls the given function exactly once.
 *
 * This function calls the function given by the **func** parameter exactly
 * one time for the given **once** parameter, no matter how many times
 * OE_H_Once() is called. OE_Once() may be called safely from different threads
 * and is typically used as a thread-safe mechanism for performing one-time
 * initialization, as in the example below.
 *
 *     static OE_H_OnceType _once = OE_H_ONCE_INITIALIZER;
 *
 *     static void _Initialize(void)
 *     {
 *         // Perform one time initialization here!
 *     }
 *
 *     ...
 *
 *     OE_H_Once(&_once, _Initialize);
 *
 * The **_Initialize** function is called by the first thread to call OE_Once()
 * for the *_once* variable.
 *
 * @param once The variable used to synchronize one-time call to **func**.
 *
 * @return Returns zero on success.
 */
int OE_H_Once(
    OE_H_OnceType* once,
    void (*func)(void));

/**
 * Initialize a mutex.
 *
 * This function initializes a mutex. All mutexes are recursive. Once
 * initialized, multiple threads can use this mutex to synchronoze access
 * to data. See OE_H_MutexLock() and OE_H_MutexUnlock().
 *
 * @param mutex Initialize this mutex.
 *
 * @return Return zero on success.
 */
int OE_H_MutexInit(OE_H_Mutex* Lock);

/**
 * Acquires a lock on a mutex.
 *
 * This function acquires a lock on a mutex.
 *
 * @param mutex Acquire a lock on this mutex.
 *
 * @return Returns zero on success.
 */
int OE_H_MutexLock(OE_H_Mutex* Lock);

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
 */
int OE_H_MutexTryLock(OE_H_Mutex* mutex);

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
 */
int OE_H_MutexUnlock(OE_H_Mutex* mutex);

/**
 * Destroys a mutex.
 *
 * This function destroys a mutex that was initialized with OE_H_MutexInit().
 *
 * @param Destroy this mutex.
 *
 * @return Returns zero on success.
 */
int OE_H_MutexDestroy(OE_H_Mutex* mutex);

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
int OE_H_ThreadKeyCreate(
    OE_H_ThreadKey* key);

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
int OE_H_ThreadKeyDelete(
    OE_H_ThreadKey key);

/**
 * Sets the value of a thread-specific data entry.
 *
 * This funciton sets the value of a thread-specific data (TSD) entry
 * associated with the given key.
 *
 * @param key Set the TSD entry associated with this key.
 * @param value Set the TSD entry to this value.
 *
 * @return Returns zero on success.
 */
int OE_H_ThreadSetSpecific(
    OE_H_ThreadKey key,
    void* value);

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
void* OE_H_ThreadGetSpecific(
    OE_H_ThreadKey key);

OE_EXTERNC_END

#endif /* _HOSTTHREAD_H */
