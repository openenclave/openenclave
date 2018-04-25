// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

/*
 Host allocation for callouts

 Facilitate small and nested allocations of host memory. Data is orgranized in
 buckets with embedded metadata, with one "active" bucket (to pull allocations
 from) and one "standby" bucket. "active" put to standby on underflow (i.e.,
 freeing from a diferent bucket than the "active").

*/

#include <openenclave/bits/atexit.h>
#include <openenclave/enclave.h>

#ifndef MAX
#define MAX(a, b) (((a) > b) ? (a) : (b))
#endif

#ifndef INT32_MAX
#define INT32_MAX 0x7FFFFFFF
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

static size_t _bucketMinSize = 4096;

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

// OE_Once() replacement to work around recursion limitation
static struct OnceType
{
    OE_Spinlock lock;
    int initialized;
} _HostStackInitialized = {OE_SPINLOCK_INITIALIZER};

static void _Once(struct OnceType* once, void (*f)(void))
{
    if (!once->initialized)
    {
        OE_SpinLock(&once->lock);
        if (!((volatile struct OnceType*)once)->initialized)
            f();
        asm volatile ("":::"memory");
        once->initialized = 1;
        OE_SpinUnlock(&once->lock);
    }
}

static OE_ThreadKey _HostStackTlsKey;

static void _HostStackInit(void)
{
    if (OE_ThreadKeyCreate(&_HostStackTlsKey, NULL))
    {
        OE_Abort();
    }
}

// cleanup handler for regular exit
static void _FreeThreadBucket(void* arg)
{
    ThreadBuckets* tb = (ThreadBuckets*)arg;
    if (tb->standbyHost)
    {
        OE_HostFree((void*)tb->standbyHost);
        tb->standbyHost = NULL;
    }
    if (tb->activeHost && (tb->cached.baseFree == 0))
    {
        OE_HostFree((void*)tb->activeHost);
        tb->activeHost = NULL;
    }

    tb->flags |= THREAD_BUCKET_FLAG_RUNDOWN;
}

static ThreadBuckets* _GetThreadBuckets()
{
    ThreadBuckets* tb;

    _Once(&_HostStackInitialized, _HostStackInit);
    tb = OE_ThreadGetSpecific(_HostStackTlsKey);
    if (tb == NULL)
    {
        if ((tb = (ThreadBuckets*)OE_Sbrk(sizeof(ThreadBuckets))) == (void*)-1)
            return NULL;

        *tb = (ThreadBuckets){};
        OE_ThreadSetSpecific(_HostStackTlsKey, tb);
        __cxa_atexit(_FreeThreadBucket, tb, NULL);
    }

    // Under normal operation, there is no reentrency. There could be if the
    // host attacked us (by unmapping host memory & forcing a pagefault).
    if (tb->flags & THREAD_BUCKET_FLAG_BUSY)
        OE_Abort();

    tb->flags |= THREAD_BUCKET_FLAG_BUSY;
    return tb;
}

static void _PutThreadBuckets(ThreadBuckets* tb)
{
    OE_Assert(tb->flags & THREAD_BUCKET_FLAG_BUSY);
    tb->flags &= ~THREAD_BUCKET_FLAG_BUSY;
}

// 0 success, error otherwise
static int _FetchBucketElement(const volatile void* p, BucketElement* contents)
{
    if (!OE_IsOutsideEnclave((void*)p, sizeof(BucketElement)))
        return -1;
    volatile BucketElement* eHost = (BucketElement*)p;
    contents->bucket = eHost->bucket;
    return 0;
}

// 0 success, error otherwise. <contents> could be modified in error-code.
static int _FetchBucket(const volatile void* p, Bucket* contents)
{
    if (!OE_IsOutsideEnclave((void*)p, sizeof(Bucket)))
        return -1;

    {
        volatile Bucket* bHost = (Bucket*)p;
        contents->size = bHost->size;
        contents->baseFree = bHost->baseFree;
    }

    if (contents->size >= INT32_MAX)
        return -1;
    if (contents->baseFree > contents->size)
        return -1;
    if (!OE_IsOutsideEnclave((void*)p, sizeof(Bucket) + contents->size))
        return -1;

    return 0;
}

static size_t _GetBucketAvailableBytes(const Bucket* b)
{
    OE_Assert(b->size >= b->baseFree);
    return b->size - b->baseFree;
}

void* OE_HostAllocForCallHost(size_t size)
{
    ThreadBuckets* tb; // deliberate non-init
    void* retVal = NULL;

    if (!size || (size > INT32_MAX))
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
                OE_Abort();

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
            if ((bHost = (Bucket*)OE_HostMalloc(allocSize)) == NULL)
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

void OE_HostFreeForCallHost(void* p)
{
    BucketElement e = {};
    volatile BucketElement* eHost; // deliberate non-init
    ThreadBuckets* tb;             // deliberate non-init

    if (p == NULL)
        return;

    eHost = (BucketElement*)p - 1;
    if (_FetchBucketElement(eHost, &e))
        OE_Abort();

    tb = _GetThreadBuckets();
    OE_Assert(tb != NULL);

    OE_Assert(
        (tb->activeHost != NULL) || (tb->flags & THREAD_BUCKET_FLAG_RUNDOWN));

    if (e.bucket != tb->activeHost)
    {
        // underflow - rotate active bucket into standby
        if (tb->activeHost != NULL)
        {
            OE_Assert(tb->activeHost->baseFree == 0);
            OE_Assert(tb->cached.baseFree == 0);
        }

        // free old buckets
        if (tb->flags & THREAD_BUCKET_FLAG_RUNDOWN)
        {
            // on rundown, do not bother to cache
            OE_Assert(tb->standbyHost == NULL);
            if (tb->activeHost)
                OE_HostFree((void*)tb->activeHost);
        }
        else
        {
            if (tb->standbyHost)
                OE_HostFree((void*)tb->standbyHost);
            tb->standbyHost = tb->activeHost;
        }

        if (_FetchBucket(e.bucket, &tb->cached))
            OE_Abort();

        tb->activeHost = e.bucket;
    }

    // element in bucket?
    if ((size_t)eHost < (size_t)(&tb->activeHost->elements))
        OE_Abort();

    if ((size_t)p >= (size_t)(&tb->activeHost->elements) + tb->cached.size)
        OE_Abort();

    tb->cached.baseFree = (size_t)(eHost) - (size_t)(&tb->activeHost->elements);

    if ((tb->flags & THREAD_BUCKET_FLAG_RUNDOWN) && (tb->cached.baseFree == 0))
    {
        // on rundown, do not bother to cache
        OE_HostFree((void*)tb->activeHost);
        tb->activeHost = NULL;
    }
    else
    {
        // write bucket info back
        tb->activeHost->baseFree = tb->cached.baseFree;
    }

    _PutThreadBuckets(tb);
}
