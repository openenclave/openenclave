// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "memalign.h"

#if defined(__linux__)
#include <malloc.h>
#elif defined(_WIN32)
#include <Windows.h>
#endif

void* oe_memalign(size_t alignment, size_t size)
{
#if defined(__linux__)
    extern void* memalign(size_t alignment, size_t size);
    return memalign(alignment, size);
#elif defined(_WIN32)
    return _aligned_malloc(size, alignment);
#endif
}

void oe_memalign_free(void* ptr)
{
#if defined(__linux__)
    free(ptr);
#elif defined(_WIN32)
    _aligned_free(ptr);
#endif
}
