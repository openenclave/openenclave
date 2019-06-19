// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "../hostthread.h"
#include <assert.h>
#include <openenclave/host.h>

/*
**==============================================================================
**
** oe_thread
**
**==============================================================================
*/

oe_thread oe_thread_self(void)
{
    return GetCurrentThreadId();
}

int oe_thread_equal(oe_thread thread1, oe_thread thread2)
{
    return thread1 == thread2;
}

/*
**==============================================================================
**
** oe_once_type
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

int oe_once(oe_once_type* once, void (*func)(void))
{
    return InitOnceExecuteOnce(once, OnceHelper, func, NULL);
}

/*
**==============================================================================
**
** oe_mutex
**
**==============================================================================
*/

int oe_mutex_init(oe_mutex* Lock)
{
    HANDLE h = CreateMutex(NULL, FALSE, NULL);

    if (h != NULL)
    {
        *Lock = h;
        return 0;
    }
    return 1;
}

int oe_mutex_lock(oe_mutex* Lock)
{
    oe_mutex new_lock;

    if (*Lock == OE_H_MUTEX_INITIALIZER)
    {
        if (oe_mutex_init(&new_lock))
            return 1;
        if (InterlockedCompareExchangePointer(
                Lock, new_lock, OE_H_MUTEX_INITIALIZER) !=
            OE_H_MUTEX_INITIALIZER)
        {
            if (oe_mutex_destroy(&new_lock))
                return 1;
        }
    }

    return WaitForSingleObject(*Lock, INFINITE) != WAIT_OBJECT_0;
}

int oe_mutex_unlock(oe_mutex* Lock)
{
    return !ReleaseMutex(*Lock);
}

int oe_mutex_destroy(oe_mutex* Lock)
{
    return !CloseHandle(*Lock);
}

/*
**==============================================================================
**
** oe_thread_key
**
**==============================================================================
*/

int oe_thread_key_create(oe_thread_key* key)
{
    oe_thread_key k;
    k = TlsAlloc();
    if (k == TLS_OUT_OF_INDEXES)
        return 1;

    *key = k;
    return 0;
}

int oe_thread_key_delete(oe_thread_key key)
{
    return !TlsFree(key);
}

int oe_thread_setspecific(oe_thread_key key, void* value)
{
    return !TlsSetValue(key, value);
}

void* oe_thread_getspecific(oe_thread_key key)
{
    return TlsGetValue(key);
}

/*
**==============================================================================
**
** oe_thread_create
**
**==============================================================================
*/
int oe_thread_create(oe_thread* thread, oe_thread_op_t op, oe_thread_arg_t arg)
{
    *thread = CreateThread(NULL, 0, op, arg, 0, NULL);
    return NULL == *thread;
}

/*
**==============================================================================
**
** oe_thread_join
**
**==============================================================================
*/
void oe_thread_join(oe_thread thread)
{
    WaitForSingleObject(thread, INFINITE);
}
