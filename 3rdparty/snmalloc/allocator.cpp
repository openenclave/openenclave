// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/advanced/allocator.h>

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
#define SNMALLOC_SGX
#define SNMALLOC_USE_SMALL_CHUNKS
#define SNMALLOC_EXTERNAL_THREAD_ALLOC
#define SNMALLOC_NAME_MANGLE(a) oe_allocator_##a

// Enable the Open Enclave PAL(Platform Abstraction Layer) for Open Enclave,
// see pal_open_enclave.h for details
#include "./snmalloc/src/override/malloc.cc"

void oe_allocator_init(void* heap_start_address, void* heap_end_address)
{
    snmalloc::PALOpenEnclave::setup_initial_range(
        heap_start_address, heap_end_address);
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
