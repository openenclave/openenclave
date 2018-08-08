// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

/*
 Host allocation for callouts

 Facilitate small and nested allocations of host memory. Data is organized in
 buckets with embedded metadata, with one "active" bucket (to pull allocations
 from) and one "standby" bucket. "active" put to standby on underflow (i.e.,
 freeing from a different bucket than the "active").

*/

#include <openenclave/enclave.h>
#include <openenclave/internal/atexit.h>
#include <openenclave/internal/enclavelibc.h>

#ifndef MAX
#define MAX(a, b) (((a) > (b)) ? (a) : (b))
#endif

struct Bucket;

typedef struct BucketElement
{
    struct Bucket* bucket;
    char data[0];
} BucketElement;

typedef struct Bucket
{
    size_t size;     // capacity in bytes of <elements>
    size_t baseFree; // byte-offset into <elements> of first free byte
    BucketElement elements[0];
} Bucket;

static const size_t _bucketMinSize = 4096;

typedef enum ThreadBucketFlags {
    THREAD_BUCKET_FLAG_BUSY = 1,
    THREAD_BUCKET_FLAG_RUNDOWN = 2,
} ThreadBucketFlags;

// per thread struct to hold the active and standby buckets
typedef struct ThreadBuckets
{
    volatile Bucket* activeHost;
    volatile Bucket* standbyHost;
    Bucket cached; // valid if activeHost != NULL
    ThreadBucketFlags flags;
} ThreadBuckets;

// oe_once() replacement to work around recursion limitation
static struct OnceType
{
    oe_spinlock_t lock;
    int initialized;
} _HostStackInitialized = {OE_SPINLOCK_INITIALIZER};

static void _Once(struct OnceType* once, void (*f)(void))
{
    if (!once->initialized)
    {
        oe_spin_lock(&once->lock);
        if (!((volatile struct OnceType*)once)->initialized)
            f();
        asm volatile("" ::: "memory");
        once->initialized = 1;
        oe_spin_unlock(&once->lock);
    }
}

static oe_thread_key_t _HostStackTlsKey;

// cleanup handler for regular exit (must be visible to ocall-alloc test)
void oe_free_thread_buckets(void* arg)
{
    ThreadBuckets* tb = (ThreadBuckets*)arg;
    if (tb->standbyHost)
    {
        oe_host_free((void*)tb->standbyHost);
        tb->standbyHost = NULL;
    }
    if (tb->activeHost && (tb->cached.baseFree == 0))
    {
        oe_host_free((void*)tb->activeHost);
        tb->activeHost = NULL;
    }

    tb->flags |= THREAD_BUCKET_FLAG_RUNDOWN;
}

static void _HostStackInit(void)
{
    if (oe_thread_key_create(&_HostStackTlsKey, oe_free_thread_buckets))
    {
        oe_abort();
    }
}

static ThreadBuckets* _GetThreadBuckets()
{
    ThreadBuckets* tb;

    _Once(&_HostStackInitialized, _HostStackInit);
    tb = oe_thread_get_specific(_HostStackTlsKey);
    if (tb == NULL)
    {
        if ((tb = (ThreadBuckets*)oe_sbrk(sizeof(ThreadBuckets))) == (void*)-1)
            return NULL;

        *tb = (ThreadBuckets){};
        oe_thread_set_specific(_HostStackTlsKey, tb);
    }

    // Under normal operation, there is no reentrancy. There could be if the
    // host attacked us (by unmapping host memory & forcing a pagefault).
    if (tb->flags & THREAD_BUCKET_FLAG_BUSY)
        oe_abort();

    tb->flags |= THREAD_BUCKET_FLAG_BUSY;
    return tb;
}

static void _PutThreadBuckets(ThreadBuckets* tb)
{
    oe_assert(tb->flags & THREAD_BUCKET_FLAG_BUSY);
    tb->flags &= ~THREAD_BUCKET_FLAG_BUSY;
}

// 0 success, error otherwise
static int _FetchBucketElement(const volatile void* p, BucketElement* contents)
{
    if (!oe_is_outside_enclave((void*)p, sizeof(BucketElement)))
        return -1;
    volatile BucketElement* eHost = (BucketElement*)p;
    contents->bucket = eHost->bucket;
    return 0;
}

// 0 success, error otherwise. <contents> could be modified in error-code.
static int _FetchBucket(const volatile void* p, Bucket* contents)
{
    if (!oe_is_outside_enclave((void*)p, sizeof(Bucket)))
        return -1;

    {
        volatile Bucket* bHost = (Bucket*)p;
        contents->size = bHost->size;
        contents->baseFree = bHost->baseFree;
    }

    if (contents->size >= OE_MAX_SINT32)
        return -1;
    if (contents->baseFree > contents->size)
        return -1;
    if (!oe_is_outside_enclave((void*)p, sizeof(Bucket) + contents->size))
        return -1;

    return 0;
}

static size_t _GetBucketAvailableBytes(const Bucket* b)
{
    oe_assert(b->size >= b->baseFree);
    return b->size - b->baseFree;
}

void* oe_host_alloc_for_call_host(size_t size)
{
    ThreadBuckets* tb; // deliberate non-init
    void* retVal = NULL;

    if (!size || (size > OE_MAX_SINT32))
        return NULL;

    if ((tb = _GetThreadBuckets()) == NULL)
        return NULL;

    if ((tb->activeHost != NULL) &&
        (_GetBucketAvailableBytes(&tb->cached) >= size + sizeof(BucketElement)))
    {
        size_t off = tb->cached.baseFree;
        tb->cached.baseFree += size + sizeof(BucketElement);
        // write bucket info back
        tb->activeHost->baseFree = tb->cached.baseFree;

        volatile BucketElement* eHost =
            (BucketElement*)((char*)(&tb->activeHost->elements) + off);
        eHost->bucket = (Bucket*)tb->activeHost;
        retVal = (void*)(&eHost->data);
        goto Exit;
    }

    // need new bucket
    {
        volatile Bucket* bHost = NULL;
        tb->activeHost = NULL;

        // Do we have a standby?
        if (tb->standbyHost != NULL)
        {
            if (_FetchBucket(tb->standbyHost, &tb->cached))
                oe_abort();

            if (_GetBucketAvailableBytes(&tb->cached) >=
                size + sizeof(BucketElement))
            {
                bHost = tb->standbyHost;
                tb->standbyHost = NULL;
            }
        }

        if (bHost == NULL)
        {
            size_t allocSize = MAX(
                size + sizeof(Bucket) + sizeof(BucketElement), _bucketMinSize);
            if ((bHost = (Bucket*)oe_host_malloc(allocSize)) == NULL)
                goto Exit;

            bHost->size = tb->cached.size = allocSize - sizeof(Bucket);
        }

        tb->cached.baseFree = size + sizeof(BucketElement);
        bHost->baseFree = tb->cached.baseFree;
        bHost->elements[0].bucket = (Bucket*)bHost;
        tb->activeHost = bHost;
        retVal = (void*)(&bHost->elements[0].data);
    }

Exit:
    _PutThreadBuckets(tb);
    return retVal;
}

void oe_host_free_for_call_host(void* p)
{
    BucketElement e = {};
    volatile BucketElement* eHost; // deliberate non-init
    ThreadBuckets* tb;             // deliberate non-init

    if (p == NULL)
        return;

    eHost = (BucketElement*)p - 1;
    if (_FetchBucketElement(eHost, &e))
        oe_abort();

    tb = _GetThreadBuckets();
    oe_assert(tb != NULL);

    oe_assert(
        (tb->activeHost != NULL) || (tb->flags & THREAD_BUCKET_FLAG_RUNDOWN));

    if (e.bucket != tb->activeHost)
    {
        // underflow - rotate active bucket into standby
        if (tb->activeHost != NULL)
        {
            oe_assert(tb->activeHost->baseFree == 0);
            oe_assert(tb->cached.baseFree == 0);
        }

        // free old buckets
        if (tb->flags & THREAD_BUCKET_FLAG_RUNDOWN)
        {
            // on rundown, do not bother to cache
            oe_assert(tb->standbyHost == NULL);
            if (tb->activeHost)
                oe_host_free((void*)tb->activeHost);
        }
        else
        {
            if (tb->standbyHost)
                oe_host_free((void*)tb->standbyHost);
            tb->standbyHost = tb->activeHost;
        }

        if (_FetchBucket(e.bucket, &tb->cached))
            oe_abort();

        tb->activeHost = e.bucket;
    }

    // element in bucket?
    if ((size_t)eHost < (size_t)(&tb->activeHost->elements))
        oe_abort();

    if ((size_t)p >= (size_t)(&tb->activeHost->elements) + tb->cached.size)
        oe_abort();

    tb->cached.baseFree = (size_t)(eHost) - (size_t)(&tb->activeHost->elements);

    if ((tb->flags & THREAD_BUCKET_FLAG_RUNDOWN) && (tb->cached.baseFree == 0))
    {
        // on rundown, do not bother to cache
        oe_host_free((void*)tb->activeHost);
        tb->activeHost = NULL;
    }
    else
    {
        // write bucket info back
        tb->activeHost->baseFree = tb->cached.baseFree;
    }

    _PutThreadBuckets(tb);
}
