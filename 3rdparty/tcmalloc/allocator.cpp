// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/advanced/allocator.h>
#include <openenclave/enclave.h>
#include <tcmalloc.h>

extern "C"
{
    // tcmalloc function prototypes.
    void* tc_malloc(size_t size);
    void tc_free(void* ptr);
    void* tc_realloc(void* ptr, size_t size);
    void* tc_calloc(size_t nmemb, size_t size);
    void* tc_memalign(size_t __alignment, size_t __size);
    int tc_posix_memalign(void** ptr, size_t align, size_t size);
    size_t tc_malloc_size(void* p);

    // Open Enclave specific API.
    void tcmalloc_set_enclave_heap_range(
        uint8_t* heap_start,
        uint8_t* heap_end);

    // Implement pluggable allocator interface
    void oe_allocator_init(void* heap_start_address, void* heap_end_address)
    {
        tcmalloc_set_enclave_heap_range(
            (uint8_t*)heap_start_address, (uint8_t*)heap_end_address);
    }

    void oe_allocator_cleanup(void)
    {
    }

    void oe_allocator_thread_init(void)
    {
    }

    void oe_allocator_thread_cleanup(void)
    {
    }

    void* oe_allocator_malloc(size_t size)
    {
        return tc_malloc(size);
    }

    void oe_allocator_free(void* ptr)
    {
        tc_free(ptr);
    }

    void* oe_allocator_calloc(size_t nmemb, size_t size)
    {
        return tc_calloc(nmemb, size);
    }

    void* oe_allocator_realloc(void* ptr, size_t size)
    {
        return tc_realloc(ptr, size);
    }

    void* oe_allocator_aligned_alloc(size_t alignment, size_t size)
    {
        return tc_memalign(alignment, size);
    }

    int oe_allocator_posix_memalign(
        void** memptr,
        size_t alignment,
        size_t size)
    {
        return tc_posix_memalign(memptr, alignment, size);
    }

    size_t oe_allocator_malloc_usable_size(void* ptr)
    {
        return tc_malloc_size(ptr);
    }
}
