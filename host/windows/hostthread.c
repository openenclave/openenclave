// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "../hostthread.h"
#include <assert.h>
#include <openenclave/host.h>

/*
**==============================================================================
**
** OE_H_Thread
**
**==============================================================================
*/

OE_H_Thread OE_H_ThreadSelf(void)
{
    return GetCurrentThreadId();
}

int OE_H_ThreadEqual(OE_H_Thread thread1, OE_H_Thread thread2)
{
    return thread1 == thread2;
}

/*
**==============================================================================
**
** OE_H_OnceType
**
**==============================================================================
*/

static BOOL CALLBACK OnceHelper(
    _Inout_ PINIT_ONCE InitOnce,
    _Inout_opt_ PVOID Parameter,
    _Out_opt_ PVOID* Context)
{
    ((void (*)(void))Parameter)();
    return TRUE;
}

int OE_H_Once(OE_H_OnceType* once, void (*func)(void))
{
    return InitOnceExecuteOnce(once, OnceHelper, func, NULL);
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
    HANDLE h = CreateMutex(NULL, FALSE, NULL);

    if (h != NULL)
    {
        *Lock = h;
        return 0;
    }
    return 1;
}

int OE_H_MutexLock(OE_H_Mutex* Lock)
{
    OE_H_Mutex newLock;

    if (*Lock == OE_H_MUTEX_INITIALIZER)
    {
        if (OE_H_MutexInit(&newLock))
            return 1;
        if (InterlockedCompareExchangePointer(
                Lock, newLock, OE_H_MUTEX_INITIALIZER) !=
            OE_H_MUTEX_INITIALIZER)
        {
            if (OE_H_MutexDestroy(&newLock))
                return 1;
        }
    }

    return WaitForSingleObject(*Lock, INFINITE) != WAIT_OBJECT_0;
}

int OE_H_MutexUnlock(OE_H_Mutex* Lock)
{
    return !ReleaseMutex(*Lock);
}

int OE_H_MutexDestroy(OE_H_Mutex* Lock)
{
    return !CloseHandle(*Lock);
}

/*
**==============================================================================
**
** OE_H_ThreadKey
**
**==============================================================================
*/

int OE_H_ThreadKeyCreate(OE_H_ThreadKey* key)
{
    OE_H_ThreadKey k;
    k = TlsAlloc();
    if (k == TLS_OUT_OF_INDEXES)
        return 1;

    *key = k;
    return 0;
}

int OE_H_ThreadKeyDelete(OE_H_ThreadKey key)
{
    return !TlsFree(key);
}

int OE_H_ThreadSetSpecific(OE_H_ThreadKey key, void* value)
{
    return !TlsSetValue(key, value);
}

void* OE_H_ThreadGetSpecific(OE_H_ThreadKey key)
{
    return TlsGetValue(key);
}
