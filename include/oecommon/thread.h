#ifndef _OE_THREAD_H
#define _OE_THREAD_H

#include <stddef.h>
#include "defs.h"

OE_EXTERNC_BEGIN

/*
**==============================================================================
**
** OE_Thread
**
**==============================================================================
*/

typedef unsigned long OE_Thread;

typedef struct _OE_ThreadAttr 
{
    unsigned long long reserved[8];
}
OE_ThreadAttr;

OE_Thread OE_ThreadSelf(void);

int OE_ThreadEqual(OE_Thread thread1, OE_Thread thread2);

#if 0
int OE_ThreadCreate(
    OE_Thread* thread, 
    const OE_ThreadAttr* attr,
    void* (*func)(void* arg), 
    void* arg);
#endif

#if 0
int OE_ThreadJoin(
    OE_Thread thread, 
    void** ret);
#endif

#if 0
int OE_ThreadDetach(
    OE_Thread thread);
#endif

/*
**==============================================================================
**
** OE_Once
**
**==============================================================================
*/

typedef unsigned int OE_OnceType;

#define OE_ONCE_INITIALIZER 0

int OE_Once(
    OE_OnceType* once, 
    void (*func)(void));

/*
**==============================================================================
**
** OE_Spinlock
**
**==============================================================================
*/

#define OE_SPINLOCK_INITIALIZER 0

typedef volatile unsigned int OE_Spinlock;

int OE_SpinInit(OE_Spinlock* spinlock);

int OE_SpinLock(OE_Spinlock* spinlock);

int OE_SpinUnlock(OE_Spinlock* spinlock);

int OE_SpinDestroy(OE_Spinlock* spinlock);

/*
**==============================================================================
**
** OE_Mutex
**
**==============================================================================
*/

#define OE_MUTEX_INITIALIZER { 0, 0, 0, 0, 0, 0, 0, 0 }

#define OE_MUTEX_RECURSIVE 1

typedef struct _OE_MutexAttr 
{
    unsigned long long reserved[1];
}
OE_MutexAttr;

typedef struct _OE_Mutex
{
    unsigned long long reserved[8];
}
OE_Mutex;

int OE_MutexAttrInit(
    OE_MutexAttr* attr);

int OE_MutexAttrSet(
    OE_MutexAttr* attr, int type);

int OE_MutexAttrDestroy(
    OE_MutexAttr* attr);

int OE_MutexInit(
    OE_Mutex* mutex, 
    OE_MutexAttr* attr);

int OE_MutexLock(
    OE_Mutex* mutex);

/* ATTN: implement! */
int OE_MutexTryLock(
    OE_Mutex* mutex);

int OE_MutexUnlock(
    OE_Mutex* mutex);

int OE_MutexDestroy(
    OE_Mutex* mutex);

/*
**==============================================================================
**
** OE_Cond
**
**==============================================================================
*/

#define OE_COND_INITIALIZER { 0, 0, 0, 0, 0, 0, 0, 0 }

typedef struct _OE_Cond
{
    unsigned long long reserved[8];
}
OE_Cond;

typedef struct _OE_CondAttr OE_CondAttr;

int OE_CondInit(
    OE_Cond* cond, 
    OE_CondAttr* attr);

int OE_CondDestroy(
    OE_Cond* cond);

int OE_CondWait(
    OE_Cond* cond, 
    OE_Mutex* mutex);

typedef struct timespec __oe_timespec;

int OE_CondTimedWait(
    OE_Cond* cond, 
    OE_Mutex* mutex,
    struct timespec* ts);

int OE_CondSignal(
    OE_Cond* cond);

int OE_CondBroadcast(
    OE_Cond* cond);

/*
**==============================================================================
**
** OE_ThreadKey
**
**==============================================================================
*/

#define OE_THREADKEY_INITIALIZER 0

typedef unsigned int OE_ThreadKey;

int OE_ThreadKeyCreate(
    OE_ThreadKey* key, 
    void (*destructor)(void* value));

int OE_ThreadKeyDelete(
    OE_ThreadKey key);

int OE_ThreadSetSpecific(
    OE_ThreadKey key, 
    const void* value);

void* OE_ThreadGetSpecific(
    OE_ThreadKey key);

OE_EXTERNC_END

#endif /* _OE_THREAD_H */
