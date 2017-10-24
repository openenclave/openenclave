#include <openenclave/enclave.h>
#include <openenclave/bits/globals.h>
#include <openenclave/bits/fault.h>
#include <openenclave/bits/malloc.h>

#define OE_ENABLE_MALLOC_WRAPPERS
#define HAVE_MMAP 0
#define LACKS_UNISTD_H
#define LACKS_SYS_PARAM_H
#define LACKS_SYS_TYPES_H
#define LACKS_TIME_H
#define NO_MALLOC_STATS 1
#define MALLOC_FAILURE_ACTION
#define MORECORE sbrk
#define ABORT OE_Abort()
#define USE_DL_PREFIX
#define LACKS_STDLIB_H
#define LACKS_STRING_H
#define LACKS_ERRNO_H
#define size_t size_t
#define ptrdiff_t ptrdiff_t
#define memset OE_Memset
#define memcpy OE_Memcpy
#define sbrk OE_Sbrk
#define EINVAL 28
#define ENOMEM 49

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstrict-prototypes"
#pragma GCC diagnostic ignored "-Wmissing-prototypes"
#include "../3rdparty/dlmalloc/dlmalloc/malloc.c"

#if defined(OE_ENABLE_MALLOC_WRAPPERS)

static OE_Spinlock _spin = OE_SPINLOCK_INITIALIZER;

static OE_AllocationFailureCallback _failureCallback;

void OE_SetAllocationFailureCallback(OE_AllocationFailureCallback function)
{
    OE_SpinLock(&_spin);
    _failureCallback = function;
    OE_SpinUnlock(&_spin);
}

void *malloc(size_t size)
{
    void* p;

    OE_SpinLock(&_spin);
    p = dlmalloc(size);
    OE_SpinUnlock(&_spin);

    if (!p && _failureCallback)
        _failureCallback(__FILE__, __LINE__, __FUNCTION__, size);

    return p;
}

void free(void *ptr)
{
    OE_SpinLock(&_spin);
    dlfree(ptr);
    OE_SpinUnlock(&_spin);
}

void *calloc(size_t nmemb, size_t size)
{
    void* p;

    OE_SpinLock(&_spin);
    p = dlcalloc(nmemb, size);
    OE_SpinUnlock(&_spin);

    if (!p && _failureCallback)
        _failureCallback(__FILE__, __LINE__, __FUNCTION__, nmemb * size);

    return p;
}

void *realloc(void *ptr, size_t size)
{
    void* p;

    OE_SpinLock(&_spin);
    p = dlrealloc(ptr, size);
    OE_SpinUnlock(&_spin);

    if (!p && _failureCallback)
        _failureCallback(__FILE__, __LINE__, __FUNCTION__, size);

    return p;
}

int posix_memalign(void **memptr, size_t alignment, size_t size)
{
    int rc;

    OE_SpinLock(&_spin);
    rc = dlposix_memalign(memptr, alignment, size);
    OE_SpinUnlock(&_spin);

    if (rc != 0 && _failureCallback)
        _failureCallback(__FILE__, __LINE__, __FUNCTION__, size);

    return rc;
}

void *memalign(size_t alignment, size_t size)
{
    void* p;

    OE_SpinLock(&_spin);
    p = dlmemalign(alignment, size);
    OE_SpinUnlock(&_spin);

    if (!p && _failureCallback)
        _failureCallback(__FILE__, __LINE__, __FUNCTION__, size);

    return p;
}

#else /* OE_ENABLE_MALLOC_WRAPPERS */

void OE_SetAllocationFailureCallback(OE_AllocationFailureCallback function)
{
    /* Empty! */
}

OE_WEAK_ALIAS(dlmalloc, malloc);
OE_WEAK_ALIAS(dlcalloc, calloc);
OE_WEAK_ALIAS(dlrealloc, realloc);
OE_WEAK_ALIAS(dlfree, free);
OE_WEAK_ALIAS(dlmemalign, memalign);
OE_WEAK_ALIAS(dlposix_memalign, posix_memalign);

#endif /* OE_ENABLE_MALLOC_WRAPPERS */
