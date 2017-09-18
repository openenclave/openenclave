#include <pthread.h>
#include <assert.h>
#include <openenclave/host.h>

OE_STATIC_ASSERT(sizeof(OE_Mutex) == sizeof(pthread_mutex_t));
OE_STATIC_ASSERT(sizeof(OE_Cond) == sizeof(pthread_cond_t));
OE_STATIC_ASSERT(sizeof(OE_ThreadAttr) == sizeof(pthread_attr_t));
OE_STATIC_ASSERT(sizeof(OE_Thread) == sizeof(pthread_t));
OE_STATIC_ASSERT(sizeof(OE_OnceType) == sizeof(pthread_once_t));
OE_STATIC_ASSERT(sizeof(OE_Spinlock) == sizeof(pthread_spinlock_t));

/*
**==============================================================================
**
** OE_Thread
**
**==============================================================================
*/

OE_Thread OE_ThreadSelf(void)
{
    return (OE_Thread)pthread_self();
}

int OE_ThreadEqual(OE_Thread thread1, OE_Thread thread2)
{
    return pthread_equal((pthread_t)thread1, (pthread_t)thread2);
}

#if 0
int OE_ThreadCreate(
    OE_Thread* thread, 
    const OE_ThreadAttr* attr,
    void* (*start_routine)(void* arg), 
    void* arg)
{
    return pthread_create(
        (pthread_t*)thread,
        (pthread_attr_t*)attr,
        start_routine,
        arg);
}
#endif

#if 0
int OE_ThreadJoin(
    OE_Thread thread, 
    void** ret)
{
    return pthread_join((pthread_t)thread, ret);
}
#endif

#if 0
int OE_ThreadDetach(
    OE_Thread thread)
{
    return pthread_detach((pthread_t)thread);
}
#endif

/*
**==============================================================================
**
** OE_Once
**
**==============================================================================
*/

int OE_Once(
    OE_OnceType* once, 
    void (*func)(void))
{
    return pthread_once((pthread_once_t*)once, func);
}

/*
**==============================================================================
**
** OE_Mutex
**
**==============================================================================
*/

int OE_MutexInit(
    OE_Mutex* mutex)
{
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);

    int rc = pthread_mutex_init((pthread_mutex_t*)mutex, &attr);

    pthread_mutexattr_destroy(&attr);

    return rc;
}

int OE_MutexLock(OE_Mutex* mutex)
{
    return pthread_mutex_lock((pthread_mutex_t*)mutex);
}

int OE_MutexTryLock(OE_Mutex* mutex)
{
    return pthread_mutex_trylock((pthread_mutex_t*)mutex);
}

int OE_MutexUnlock(OE_Mutex* mutex)
{
    return pthread_mutex_unlock((pthread_mutex_t*)mutex);
}

int OE_MutexDestroy(
    OE_Mutex* mutex)
{
    return pthread_mutex_destroy((pthread_mutex_t*)mutex);
}

/*
**==============================================================================
**
** OE_Cond
**
**==============================================================================
*/

int OE_CondInit(OE_Cond* cond)
{
    return pthread_cond_init((pthread_cond_t*)cond, NULL);
}

int OE_CondDestroy(
    OE_Cond* cond)
{
    return pthread_cond_destroy((pthread_cond_t*)cond);
}

int OE_CondWait(
    OE_Cond* cond, 
    OE_Mutex* mutex)
{
    return pthread_cond_wait((pthread_cond_t*)cond, (pthread_mutex_t*)mutex);
}

int OE_CondSignal(
    OE_Cond* cond)
{
    return pthread_cond_signal((pthread_cond_t*)cond);
}

int OE_CondBroadcast(
    OE_Cond* cond)
{
    return pthread_cond_broadcast((pthread_cond_t*)cond);
}

/*
**==============================================================================
**
** OE_ThreadKey
**
**==============================================================================
*/

int OE_ThreadKeyCreate(
    OE_ThreadKey* key, 
    void (*destructor)(void* value))
{
    return pthread_key_create((pthread_key_t*)key, destructor);
}

int OE_ThreadKeyDelete(
    OE_ThreadKey key)
{
    return pthread_key_delete((pthread_key_t)key);
}

int OE_ThreadSetSpecific(
    OE_ThreadKey key, 
    const void* value)
{
    return pthread_setspecific((pthread_key_t)key, value);
}

void* OE_ThreadGetSpecific(
    OE_ThreadKey key)
{
    return pthread_getspecific((pthread_key_t)key);
}
