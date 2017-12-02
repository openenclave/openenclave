#include <openenclave/enclave.h>
#include <openenclave/thread.h>
#include <openenclave/bits/sgxtypes.h>
#include <openenclave/bits/malloc.h>
#include <stdio.h>
#include <assert.h>

static void __wait(
    volatile int *addr, 
    volatile int *waiters, 
    int val, 
    int priv);

static void __wake(
    volatile void *addr, 
    int cnt, 
    int priv);

#define _PTHREAD_IMPL_H
#define malloc musl_malloc
#define free musl_free
#define realloc musl_realloc
#include "../3rdparty/musl/musl/src/malloc/malloc.c"
#undef malloc
#undef free
#undef realloc

static OE_Mutex _mutex = OE_MUTEX_INITIALIZER;

static void __wait(
    volatile int *addr, 
    volatile int *waiters, 
    int val, /* will be 1 */
    int priv)
{
    int spins = 100;

    while (spins-- && (!waiters || !*waiters)) 
    {
        if (*addr == val) 
            a_spin();
        else 
            return;
    }

    if (waiters) 
        a_inc(waiters);

    while (*addr == val) 
    {
        OE_MutexLock(&_mutex);

        if (*addr != val)
        {
            OE_MutexUnlock(&_mutex);
            break;
        }

        OE_MutexUnlock(&_mutex);
    }

    if (waiters) 
        a_dec(waiters);
}

static void __wake(
    volatile void *addr, 
    int cnt, /* will be 1 */
    int priv) /* ignored */
{
    if (addr)
    {
        OE_MutexLock(&_mutex);
        *((volatile int*)addr) = 0;
        OE_MutexUnlock(&_mutex);
    }
}

/*
**==============================================================================
**
** malloc wrappers around MUSL calls (with failure callbacks)
**
**==============================================================================
*/

/* Enable MUSL locking on first entry */
OE_INLINE void _EnableMUSLLocking()
{
    if (libc.threads_minus_1 == 0)
    {
        static OE_Spinlock _lock = OE_SPINLOCK_INITIALIZER;
        OE_SpinLock(&_lock);
        libc.threads_minus_1 = 1;
        OE_SpinUnlock(&_lock);
    }
}

static OE_AllocationFailureCallback _failureCallback;

static OE_Spinlock _lock = OE_SPINLOCK_INITIALIZER;

void OE_SetAllocationFailureCallback(OE_AllocationFailureCallback function)
{
    _failureCallback = function;
}

void *malloc(size_t size)
{
    _EnableMUSLLocking();
    void* p = musl_malloc(size);

    if (!p && size)
    {
        errno = ENOMEM;

        if (_failureCallback)
            _failureCallback(__FILE__, __LINE__, __FUNCTION__, size);
    }

    return p;
}

void free(void *ptr)
{
    _EnableMUSLLocking();
    musl_free(ptr);
}

void *calloc(size_t nmemb, size_t size)
{
    void *musl_calloc(size_t nmemb, size_t size);

    _EnableMUSLLocking();
    void* p = musl_calloc(nmemb, size);

    if (!p && nmemb && size)
    {
        errno = ENOMEM;

        if (_failureCallback)
            _failureCallback(__FILE__, __LINE__, __FUNCTION__, nmemb * size);
    }

    return p;
}

void *realloc(void *ptr, size_t size)
{
    _EnableMUSLLocking();
    void* p = musl_realloc(ptr, size);

    if (!p && size)
    {
        errno = ENOMEM;

        if (_failureCallback)
            _failureCallback(__FILE__, __LINE__, __FUNCTION__, size);
    }

    return p;
}

int posix_memalign(void **memptr, size_t alignment, size_t size)
{
    int musl_posix_memalign(void **memptr, size_t alignment, size_t size);

    _EnableMUSLLocking();
    int rc = musl_posix_memalign(memptr, alignment, size);

    if (rc != 0 && size)
    {
        errno = ENOMEM;

        if (_failureCallback)
            _failureCallback(__FILE__, __LINE__, __FUNCTION__, size);
    }

    return rc;
}

void *memalign(size_t alignment, size_t size)
{
    void *musl_memalign(size_t alignment, size_t size);

    _EnableMUSLLocking();
    void* p = musl_memalign(alignment, size);

    if (!p && size)
    {
        errno = ENOMEM;

        if (_failureCallback)
            _failureCallback(__FILE__, __LINE__, __FUNCTION__, size);
    }

    return p;
}
