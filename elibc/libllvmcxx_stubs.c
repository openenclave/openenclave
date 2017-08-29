#include <pthread.h>
#include <assert.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-prototypes"

/*
**==============================================================================
**
** pthread.h
**
**==============================================================================
*/

int __libllvmcxx_pthread_create(
    pthread_t* thread,
    const pthread_attr_t* attr,
    void* (*start_routine)(void* arg),
    void* arg)
{
    assert("__libllvmcxx_pthread_create(): panic" == NULL);
}

int __libllvmcxx_pthread_join(pthread_t thread, void** ret)
{
    assert("__libllvmcxx_pthread_join(): panic" == NULL);
}

int __libllvmcxx_pthread_detach(pthread_t thread)
{
    assert("__libllvmcxx_pthread_detach(): panic" == NULL);
}
