// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

/*
    Wrapper functions for host allocation tracking and atexit handling.
 */

#include <openenclave/enclave.h>
#include <openenclave/internal/atexit.h>
#include <openenclave/internal/tests.h>
#include <map>
#include <vector>
// And local wrap
#include "wrap.h"

static struct
{
    std::vector<std::pair<void (*)(void*), void*>> exits;
    std::map<void*, size_t> allocations;
} stats;

OE_EXTERNC_BEGIN

int test_cxa_atexit(void (*func)(void*), void* arg, void* dso_handle)
{
    stats.exits.push_back({func, arg});
    return __cxa_atexit(func, arg, dso_handle);
}

void* test_host_malloc(size_t size)
{
    void* p;

    p = oe_host_malloc(size);
    if (p)
    {
        auto ins = stats.allocations.insert(std::pair<void*, size_t>(p, size));
        OE_TEST(ins.second == true);
    }
    return p;
}

void test_host_free(void* ptr)
{
    if (ptr)
        OE_TEST(stats.allocations.erase(ptr) == 1);
    oe_host_free(ptr);
}

oe_result_t test_thread_key_create(
    oe_thread_key_t* key,
    void (*destructor)(void* value))
{
    // Ignore the destrutor.
    return oe_thread_key_create(key, NULL);
}

void test_free_thread_buckets(void* arg);

oe_result_t test_thread_setspecific(oe_thread_key_t key, const void* value)
{
    oe_result_t result;

    if ((result = oe_thread_setspecific(key, value)) == OE_OK)
        test_cxa_atexit(test_free_thread_buckets, (void*)value, NULL);

    return OE_OK;
}

OE_EXTERNC_END

size_t GetAllocationCount()
{
    return stats.allocations.size();
}

size_t GetAllocationBytes()
{
    size_t s = 0;
    for (auto e : stats.allocations)
        s += e.second;
    return s;
}

void Exit()
{
    for (auto e : stats.exits)
        e.first(e.second);
}
