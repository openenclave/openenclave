// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "../hostthread.h"
#include <assert.h>
#include <openenclave/host.h>
#include <pthread.h>

/*
**==============================================================================
**
** oe_thread
**
**==============================================================================
*/

oe_thread oe_thread_self(void)
{
    return pthread_self();
}

int oe_thread_equal(oe_thread thread1, oe_thread thread2)
{
    return pthread_equal(thread1, thread2);
}

/*
**==============================================================================
**
** oe_once_type
**
**==============================================================================
*/

int oe_once(oe_once_type* once, void (*func)(void))
{
    return pthread_once(once, func);
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
    int err;

    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    if ((err = pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE_NP)) !=
        0)
        return err;
    pthread_mutex_init(Lock, &attr);
    pthread_mutexattr_destroy(&attr);
    return 0;
}

int oe_mutex_lock(oe_mutex* Lock)
{
    return pthread_mutex_lock(Lock);
}

int oe_mutex_unlock(oe_mutex* Lock)
{
    return pthread_mutex_unlock(Lock);
}

int oe_mutex_destroy(oe_mutex* Lock)
{
    return pthread_mutex_destroy(Lock);
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
    return pthread_key_create(key, NULL);
}

int oe_thread_key_delete(oe_thread_key key)
{
    return pthread_key_delete(key);
}

int oe_thread_setspecific(oe_thread_key key, void* value)
{
    return pthread_setspecific(key, value);
}

void* oe_thread_getspecific(oe_thread_key key)
{
    return pthread_getspecific(key);
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
    return pthread_create(thread, NULL, op, arg);
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
    pthread_join(thread, NULL);
}
