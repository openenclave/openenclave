// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/bits/sgx/sgxtypes.h>
#include "../../oe_alloc_thread.h"
#include "../../oe_nodebug_alloc.h"

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

#define USE_RESERVE_MULTIPLE 1
#define IS_ADDRESS_SPACE_CONSTRAINED

// In standard configuration, snmalloc defines the oe_* symbols
// directly. In debug configuration, snmalloc defines oe_nodebug_* symbols
// instead, and oe_* symbols are directed to the debug shim.
#if defined(OE_USE_DEBUG_MALLOC)
#define SNMALLOC_NAME_MANGLE(a) oe_nodebug_##a

extern "C" void* oe_malloc(size_t size)
{
    return oe_debug_malloc(size);
}

extern "C" void* oe_calloc(size_t nmemb, size_t size)
{
    return oe_debug_calloc(nmemb, size);
}

extern "C" void* oe_realloc(void* ptr, size_t size)
{
    return oe_debug_realloc(ptr, size);
}

extern "C" void* oe_memalign(size_t alignment, size_t size)
{
    return oe_debug_memalign(alignment, size);
}

extern "C" void* oe_free(void* ptr, size_t size)
{
    return oe_debug_free(ptr, size);
}

extern "C" size_t oe_malloc_usable_size(void* ptr)
{
    return oe_debug_malloc_usable_size(ptr);
}
#else
#define SNMALLOC_NAME_MANGLE(a) oe_##a
#endif
// The Open Enclave runtime manages the thread local allocator pointer, see td_t
#define SNMALLOC_EXTERNAL_THREAD_ALLOC
// Enable the Open Enclave PAL(Platform Abstraction Layer) for Open Enclave,
// see pal_open_enclave.h for details
#define OPEN_ENCLAVE
#include "../../../../3rdparty/snmalloc/src/override/malloc.cc"

// A small number of places want to use the underlying allocator
// without the debug shim on top, hence those explicit symbols.
#ifndef OE_USE_DEBUG_MALLOC
extern "C" void* oe_nodebug_malloc(size_t s)
{
    return oe_malloc(s);
}
extern "C" void oe_nodebug_free(void* ptr)
{
    return oe_free(ptr);
}
extern "C" void* oe_nodebug_realloc(void* ptr, size_t s)
{
    return oe_realloc(ptr, s);
}
extern "C" void* oe_nodebug_memalign(size_t alignment, size_t size)
{
    return oe_memalign(alignment, size);
}
#endif

extern "C" void oe_alloc_thread_startup()
{
    allocator_local = current_alloc_pool()->acquire();
}

extern "C" void oe_alloc_thread_teardown()
{
    current_alloc_pool()->release(ThreadAlloc::get());
    allocator_local = nullptr;
}

typedef void (*oe_allocation_failure_callback_t)(
    const char* file,
    size_t line,
    const char* func,
    size_t size);

extern "C" void oe_set_allocation_failure_callback(
    oe_allocation_failure_callback_t function)
{
    (void)function;
}

extern "C" void oe_memalign_free(void* ptr)
{
    oe_free(ptr);
}
