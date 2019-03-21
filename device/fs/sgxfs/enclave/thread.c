// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <pthread.h>

typedef pthread_mutex_t sgx_thread_mutex_t;

typedef pthread_mutexattr_t sgx_thread_mutexattr_t;

int sgx_thread_mutex_init(
    sgx_thread_mutex_t* m,
    const sgx_thread_mutexattr_t* attr)
{
    return pthread_mutex_init(m, attr);
}

int sgx_thread_mutex_lock(pthread_mutex_t* m)
{
    return pthread_mutex_lock(m);
}

int sgx_thread_mutex_unlock(pthread_mutex_t* m)
{
    return pthread_mutex_unlock(m);
}

int sgx_thread_mutex_destroy(pthread_mutex_t* m)
{
    return pthread_mutex_destroy(m);
}
