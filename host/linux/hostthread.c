#include <pthread.h>
#include <assert.h>
#include <openenclave/host.h>
#include "../hostthread.h"

/*
**==============================================================================
**
** OE_H_Thread
**
**==============================================================================
*/

OE_H_Thread OE_H_ThreadSelf(void)
{
    return pthread_self();
}

int OE_H_ThreadEqual(OE_H_Thread thread1, OE_H_Thread thread2)
{
    return pthread_equal(thread1, thread2);
}

/*
**==============================================================================
**
** OE_H_OnceType
**
**==============================================================================
*/

int OE_H_Once(
    OE_H_OnceType* once,
    void (*func)(void))
{
    return pthread_once(once, func);
}

/*
**==============================================================================
**
** OE_H_Mutex
**
**==============================================================================
*/

int OE_H_MutexInit(OE_H_Mutex* Lock)
{
    int err;

    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    if ((err = pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE_NP)) != 0)
        return err;
    pthread_mutex_init(Lock, &attr);
    pthread_mutexattr_destroy(&attr);
    return 0;
}

int OE_H_MutexLock(OE_H_Mutex* Lock)
{
    return pthread_mutex_lock(Lock);
}

int OE_H_MutexUnlock(OE_H_Mutex* Lock)
{
    return pthread_mutex_unlock(Lock);
}

int OE_H_MutexDestroy(OE_H_Mutex* Lock)
{
    return pthread_mutex_destroy(Lock);
}

/*
**==============================================================================
**
** OE_H_ThreadKey
**
**==============================================================================
*/

int OE_H_ThreadKeyCreate(
    OE_H_ThreadKey* key)
{
    return pthread_key_create(key, NULL);
}

int OE_H_ThreadKeyDelete(
    OE_H_ThreadKey key)
{
    return pthread_key_delete(key);
}

int OE_H_ThreadSetSpecific(
    OE_H_ThreadKey key,
    void* value)
{
    return pthread_setspecific(key, value);
}

void* OE_H_ThreadGetSpecific(
    OE_H_ThreadKey key)
{
    return pthread_getspecific(key);
}

