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
#include <openenclave/internal/thread.h>

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
    size_t base_free; // byte-offset into <elements> of first free byte
    BucketElement elements[0];
} Bucket;

static const size_t _bucket_min_size = 4096;

typedef enum ThreadBucketFlags {
    THREAD_BUCKET_FLAG_BUSY = 1,
    THREAD_BUCKET_FLAG_RUNDOWN = 2,
} ThreadBucketFlags;

// per thread struct to hold the active and standby buckets
typedef struct ThreadBuckets
{
    volatile Bucket* active_host;
    volatile Bucket* standby_host;
    Bucket cached; // valid if active_host != NULL
    ThreadBucketFlags flags;
} ThreadBuckets;

// oe_once() replacement to work around recursion limitation
static struct OnceType
{
    oe_spinlock_t lock;
    int initialized;
} _host_stack_initialized = {OE_SPINLOCK_INITIALIZER};

static void _once(struct OnceType* once, void (*f)(void))
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

static oe_thread_key_t _host_stack_tls_key;

// cleanup handler for regular exit (must be visible to ocall-alloc test)
void oe_free_thread_buckets(void* arg)
{
    ThreadBuckets* tb = (ThreadBuckets*)arg;
    if (tb->standby_host)
    {
        oe_host_free((void*)tb->standby_host);
        tb->standby_host = NULL;
    }
    if (tb->active_host && (tb->cached.base_free == 0))
    {
        oe_host_free((void*)tb->active_host);
        tb->active_host = NULL;
    }

    tb->flags |= THREAD_BUCKET_FLAG_RUNDOWN;
}

static void _host_stack_init(void)
{
    if (oe_thread_key_create(&_host_stack_tls_key, oe_free_thread_buckets))
    {
        oe_abort();
    }
}

static ThreadBuckets* _get_thread_buckets()
{
    ThreadBuckets* tb;

    _once(&_host_stack_initialized, _host_stack_init);
    tb = oe_thread_getspecific(_host_stack_tls_key);
    if (tb == NULL)
    {
        if ((tb = (ThreadBuckets*)oe_sbrk(sizeof(ThreadBuckets))) == (void*)-1)
            return NULL;

        *tb = (ThreadBuckets){};
        oe_thread_setspecific(_host_stack_tls_key, tb);
    }

    // Under normal operation, there is no reentrancy. There could be if the
    // host attacked us (by unmapping host memory & forcing a pagefault).
    if (tb->flags & THREAD_BUCKET_FLAG_BUSY)
        oe_abort();

    tb->flags |= THREAD_BUCKET_FLAG_BUSY;
    return tb;
}

static void _put_thread_buckets(ThreadBuckets* tb)
{
    oe_assert(tb->flags & THREAD_BUCKET_FLAG_BUSY);
    tb->flags &= ~THREAD_BUCKET_FLAG_BUSY;
}

// 0 success, error otherwise
static int _fetch_bucket_element(const volatile void* p, BucketElement* contents)
{
    if (!oe_is_outside_enclave((void*)p, sizeof(BucketElement)))
        return -1;
    volatile BucketElement* e_host = (BucketElement*)p;
    contents->bucket = e_host->bucket;
    return 0;
}

// 0 success, error otherwise. <contents> could be modified in error-code.
static int _fetch_bucket(const volatile void* p, Bucket* contents)
{
    if (!oe_is_outside_enclave((void*)p, sizeof(Bucket)))
        return -1;

    {
        volatile Bucket* is_host = (Bucket*)p;
        contents->size = is_host->size;
        contents->base_free = is_host->base_free;
    }

    if (contents->size >= OE_INT32_MAX)
        return -1;
    if (contents->base_free > contents->size)
        return -1;
    if (!oe_is_outside_enclave((void*)p, sizeof(Bucket) + contents->size))
        return -1;

    return 0;
}

static size_t _get_bucket_available_bytes(const Bucket* b)
{
    oe_assert(b->size >= b->base_free);
    return b->size - b->base_free;
}

void* oe_host_alloc_for_call_host(size_t size)
{
    ThreadBuckets* tb; // deliberate non-init
    void* ret_val = NULL;

    if (!size || (size > OE_INT32_MAX))
        return NULL;

    if ((tb = _get_thread_buckets()) == NULL)
        return NULL;

    if ((tb->active_host != NULL) &&
        (_get_bucket_available_bytes(&tb->cached) >= size + sizeof(BucketElement)))
    {
        size_t off = tb->cached.base_free;
        tb->cached.base_free += size + sizeof(BucketElement);
        // write bucket info back
        tb->active_host->base_free = tb->cached.base_free;

        volatile BucketElement* e_host =
            (BucketElement*)((char*)(&tb->active_host->elements) + off);
        e_host->bucket = (Bucket*)tb->active_host;
        ret_val = (void*)(&e_host->data);
        goto Exit;
    }

    // need new bucket
    {
        volatile Bucket* is_host = NULL;
        tb->active_host = NULL;

        // Do we have a standby?
        if (tb->standby_host != NULL)
        {
            if (_fetch_bucket(tb->standby_host, &tb->cached))
                oe_abort();

            if (_get_bucket_available_bytes(&tb->cached) >=
                size + sizeof(BucketElement))
            {
                is_host = tb->standby_host;
                tb->standby_host = NULL;
            }
        }

        if (is_host == NULL)
        {
            size_t alloc_size = MAX(
                size + sizeof(Bucket) + sizeof(BucketElement), _bucket_min_size);
            if ((is_host = (Bucket*)oe_host_malloc(alloc_size)) == NULL)
                goto Exit;

            is_host->size = tb->cached.size = alloc_size - sizeof(Bucket);
        }

        tb->cached.base_free = size + sizeof(BucketElement);
        is_host->base_free = tb->cached.base_free;
        is_host->elements[0].bucket = (Bucket*)is_host;
        tb->active_host = is_host;
        ret_val = (void*)(&is_host->elements[0].data);
    }

Exit:
    _put_thread_buckets(tb);
    return ret_val;
}

void oe_host_free_for_call_host(void* p)
{
    BucketElement e = {};
    volatile BucketElement* e_host; // deliberate non-init
    ThreadBuckets* tb;             // deliberate non-init

    if (p == NULL)
        return;

    e_host = (BucketElement*)p - 1;
    if (_fetch_bucket_element(e_host, &e))
        oe_abort();

    tb = _get_thread_buckets();
    oe_assert(tb != NULL);

    oe_assert(
        (tb->active_host != NULL) || (tb->flags & THREAD_BUCKET_FLAG_RUNDOWN));

    if (e.bucket != tb->active_host)
    {
        // underflow - rotate active bucket into standby
        if (tb->active_host != NULL)
        {
            oe_assert(tb->active_host->base_free == 0);
            oe_assert(tb->cached.base_free == 0);
        }

        // free old buckets
        if (tb->flags & THREAD_BUCKET_FLAG_RUNDOWN)
        {
            // on rundown, do not bother to cache
            oe_assert(tb->standby_host == NULL);
            if (tb->active_host)
                oe_host_free((void*)tb->active_host);
        }
        else
        {
            if (tb->standby_host)
                oe_host_free((void*)tb->standby_host);
            tb->standby_host = tb->active_host;
        }

        if (_fetch_bucket(e.bucket, &tb->cached))
            oe_abort();

        tb->active_host = e.bucket;
    }

    // element in bucket?
    if ((size_t)e_host < (size_t)(&tb->active_host->elements))
        oe_abort();

    if ((size_t)p >= (size_t)(&tb->active_host->elements) + tb->cached.size)
        oe_abort();

    tb->cached.base_free = (size_t)(e_host) - (size_t)(&tb->active_host->elements);

    if ((tb->flags & THREAD_BUCKET_FLAG_RUNDOWN) && (tb->cached.base_free == 0))
    {
        // on rundown, do not bother to cache
        oe_host_free((void*)tb->active_host);
        tb->active_host = NULL;
    }
    else
    {
        // write bucket info back
        tb->active_host->base_free = tb->cached.base_free;
    }

    _put_thread_buckets(tb);
}
