// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
#if defined(__clang__)
#pragma clang diagnostic ignored "-Wshorten-64-to-32"
#elif defined(__GNUC__)
#pragma GCC diagnostic ignored "-Wconversion"
#pragma GCC diagnostic ignored "-Wsign-conversion"
#endif

#include <libunwind.h>
#include <pthread.h>
#include <openenclave/internal/sgxtypes.h>

//
// The cmake script copies Gtrace.c to Gtrace.inc, while deleting the following
// lines.
//
//     static __thread  unw_trace_cache_t *tls_cache;
//     static __thread  int tls_cache_destroyed;
//
// The definitions below work around lack of support for the __thread storage 
// class keyword.
//

static pthread_once_t _once = PTHREAD_ONCE_INIT;
static pthread_key_t _key;
static pthread_spinlock_t _lock;

static void _init(void)
{
    pthread_key_create(&_key,  NULL);
    pthread_spin_init(&_lock, 0);
}

typedef struct entry
{
    void* tls_cache;
    int tls_cache_destroyed;
}
entry_t;

static entry_t _entries[OE_SGX_MAX_TCS];
static size_t _num_entries;

/* Assign the next available entry if any */
static entry_t* _assign_entry(void)
{
    entry_t* entry = NULL;

    pthread_spin_lock(&_lock);
    {
        if (_num_entries != OE_SGX_MAX_TCS)
            entry = &_entries[_num_entries++];
    }
    pthread_spin_unlock(&_lock);

    return entry;
}

static entry_t* _get_entry(void)
{
    entry_t* entry;

    pthread_once(&_once, _init);

    if (!(entry = (entry_t*)pthread_getspecific(_key)))
    {
        if (!(entry = (entry_t*)_assign_entry()))
            return NULL;

        pthread_setspecific(_key, entry);
    }

    return entry;
}

#define tls_cache (*((unw_trace_cache_t**)(&(_get_entry()->tls_cache))))
#define tls_cache_destroyed _get_entry()->tls_cache_destroyed

#include "Gtrace.inc"
