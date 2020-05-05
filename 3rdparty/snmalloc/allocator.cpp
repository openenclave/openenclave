// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/internal/allocator.h>

namespace snmalloc
{
__thread void* allocator_local;

class ThreadAllocUntyped
{
  public:
    static void* get();
};

void* ThreadAllocUntyped::get()
{
    return allocator_local;
}
} // namespace snmalloc

#define OPEN_ENCLAVE
#define USE_RESERVE_MULTIPLE 1
#define IS_ADDRESS_SPACE_CONSTRAINED
#define SNMALLOC_EXTERNAL_THREAD_ALLOC
#define SNMALLOC_NAME_MANGLE(a) oe_allocator_##a

// Enable the Open Enclave PAL(Platform Abstraction Layer) for Open Enclave,
// see pal_open_enclave.h for details
#include "./snmalloc/src/override/malloc.cc"

static void* _heap_start;
static void* _heap_end;

void oe_allocator_init(void* heap_start_address, void* heap_end_address)
{
    // TODO: snmalloc's OpenEnclave PAL currently uses internal functions
    // __oe_get_heap_base and __oe_get_heap_end. Instead, it needs to
    // use these values.
    _heap_start = heap_start_address;
    _heap_end = heap_end_address;
}

void oe_allocator_cleanup(void)
{
}

void oe_allocator_thread_init(void)
{
    allocator_local = current_alloc_pool()->acquire();
}

void oe_allocator_thread_cleanup(void)
{
    current_alloc_pool()->release(ThreadAlloc::get());
    allocator_local = nullptr;
}
