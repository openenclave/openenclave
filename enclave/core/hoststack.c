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
#include <openenclave/internal/utils.h>

#ifndef MAX
#define MAX(a, b) (((a) > (b)) ? (a) : (b))
#endif

struct _bucket_t;

typedef struct _bucket_element_t
{
    struct _bucket_t* bucket;
//  char data[0];
} bucket_element_t;

OE_INLINE void* _bucket_data(
    volatile bucket_element_t* bucket_element)
{
    return (void*)(bucket_element+1);
}

OE_INLINE bucket_element_t* _bucket_element_of_data(
    void* data)
{
    return (bucket_element_t*)data - 1;
}

typedef struct _bucket_t
{
    size_t size;      // capacity in bytes of <elements>
    size_t base_free; // byte-offset into <elements> of first free byte
//  bucket_element_t elements[0];
} bucket_t;

OE_INLINE bucket_element_t* _first_bucket_element(
    volatile bucket_t* bucket)

{
    return (bucket_element_t*)(bucket+1);
}

static const size_t _bucket_min_size = 4096;

typedef enum {
    THREAD_BUCKET_FLAG_BUSY = 1,
    THREAD_BUCKET_FLAG_RUNDOWN = 2,
} thread_bucket_flags_t;

// per thread struct to hold the active and standby buckets
typedef struct _thread_buckets_t
{
    volatile bucket_t* active_host;
    volatile bucket_t* standby_host;
    thread_bucket_flags_t flags;
    bucket_t cached; // valid if active_host != NULL
} thread_buckets_t;

OE_INLINE bool _is_element_in_thread_bucket(
    volatile bucket_element_t* bucket_element,
    thread_buckets_t* tb)

{
    bucket_element_t* first_element = _first_bucket_element(tb->active_host);

    return (bucket_element >= first_element) &&
           ((size_t)bucket_element < (size_t)first_element + tb->cached.size);
}


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

        OE_ATOMIC_MEMORY_BARRIER_RELEASE();

        once->initialized = 1;
        oe_spin_unlock(&once->lock);
    }
}

static oe_thread_key_t _host_stack_tls_key;

// cleanup handler for regular exit (must be visible to ocall-alloc test)
void oe_free_thread_buckets(void* arg)
{
    thread_buckets_t* tb = (thread_buckets_t*)arg;
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

static thread_buckets_t* _get_thread_buckets()
{
    thread_buckets_t* tb;

    _once(&_host_stack_initialized, _host_stack_init);
    tb = oe_thread_getspecific(_host_stack_tls_key);
    if (tb == NULL)
    {
        if ((tb = (thread_buckets_t*)oe_sbrk(sizeof(thread_buckets_t))) == (void*)-1)
            return NULL;

        oe_memset(tb, 0, sizeof(*tb));
        oe_thread_setspecific(_host_stack_tls_key, tb);
    }

    // Under normal operation, there is no reentrancy. There could be if the
    // host attacked us (by unmapping host memory & forcing a pagefault).
    if (tb->flags & THREAD_BUCKET_FLAG_BUSY)
        oe_abort();

    tb->flags |= THREAD_BUCKET_FLAG_BUSY;
    return tb;
}

static void _put_thread_buckets(thread_buckets_t* tb)
{
    oe_assert(tb->flags & THREAD_BUCKET_FLAG_BUSY);
    tb->flags &= ~THREAD_BUCKET_FLAG_BUSY;
}

// 0 success, error otherwise
static int _fetch_bucket_element(
    const volatile void* p,
    bucket_element_t* contents)
{
    if (!oe_is_outside_enclave((void*)p, sizeof(bucket_element_t)))
        return -1;
    volatile bucket_element_t* bucket_element = (bucket_element_t*)p;
    contents->bucket = bucket_element->bucket;
    return 0;
}

// 0 success, error otherwise. <contents> could be modified in error-code.
static int _fetch_bucket(const volatile void* p, bucket_t* contents)
{
    if (!oe_is_outside_enclave((void*)p, sizeof(bucket_t)))
        return -1;

    {
        volatile bucket_t* is_host = (bucket_t*)p;
        contents->size = is_host->size;
        contents->base_free = is_host->base_free;
    }

    if (contents->size >= OE_INT32_MAX)
        return -1;
    if (contents->base_free > contents->size)
        return -1;
    if (!oe_is_outside_enclave((void*)p, sizeof(bucket_t) + contents->size))
        return -1;

    return 0;
}

static size_t _get_bucket_available_bytes(const bucket_t* b)
{
    oe_assert(b->size >= b->base_free);
    return b->size - b->base_free;
}

void* oe_host_alloc_for_call_host(size_t size)
{
    thread_buckets_t* tb; // deliberate non-init
    void* ret_val = NULL;

    if (!size || (size > OE_INT32_MAX))
        return NULL;

    if ((tb = _get_thread_buckets()) == NULL)
        return NULL;

    if ((tb->active_host != NULL) &&
        (_get_bucket_available_bytes(&tb->cached) >=
         size + sizeof(bucket_element_t)))
    {
        size_t off = tb->cached.base_free;
        tb->cached.base_free += size + sizeof(bucket_element_t);
        // write bucket info back
        tb->active_host->base_free = tb->cached.base_free;

        volatile bucket_element_t* bucket_element =
            (bucket_element_t*)((char*)_first_bucket_element(tb->active_host) + off);
        bucket_element->bucket = (bucket_t*)tb->active_host;
        ret_val = _bucket_data(bucket_element);
        goto Exit;
    }

    // need new bucket
    {
        volatile bucket_t* is_host = NULL;
        bucket_element_t* bucket_element;
        tb->active_host = NULL;

        // Do we have a standby?
        if (tb->standby_host != NULL)
        {
            if (_fetch_bucket(tb->standby_host, &tb->cached))
                oe_abort();

            if (_get_bucket_available_bytes(&tb->cached) >=
                size + sizeof(bucket_element_t))
            {
                is_host = tb->standby_host;
                tb->standby_host = NULL;
            }
        }

        if (is_host == NULL)
        {
            size_t alloc_size =
                MAX(size + sizeof(bucket_t) + sizeof(bucket_element_t),
                    _bucket_min_size);
            if ((is_host = (bucket_t*)oe_host_malloc(alloc_size)) == NULL)
                goto Exit;

            is_host->size = tb->cached.size = alloc_size - sizeof(bucket_t);
        }

        tb->cached.base_free = size + sizeof(bucket_element_t);
        is_host->base_free = tb->cached.base_free;
        bucket_element = _first_bucket_element(is_host);
        bucket_element->bucket = (bucket_t*)is_host;
        tb->active_host = is_host;
        ret_val = _bucket_data(bucket_element);
    }

Exit:
    _put_thread_buckets(tb);
    return ret_val;
}

void oe_host_free_for_call_host(void* p)
{
    bucket_element_t e = {0};
    volatile bucket_element_t* bucket_element; // deliberate non-init
    thread_buckets_t* tb;                      // deliberate non-init

    if (p == NULL)
        return;

    bucket_element = _bucket_element_of_data(p);
    if (_fetch_bucket_element(bucket_element, &e))
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
    if (!_is_element_in_thread_bucket(bucket_element,tb))
        oe_abort();

    tb->cached.base_free =
        (size_t)(bucket_element) - (size_t)_first_bucket_element(tb->active_host);

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
