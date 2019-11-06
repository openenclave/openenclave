// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_DEBUG_MALLOC_H
#define _OE_DEBUG_MALLOC_H

#include <openenclave/bits/types.h>

void* oe_debug_malloc(size_t size);

void oe_debug_free(void* ptr);

void* oe_debug_calloc(size_t nmemb, size_t size);

void* oe_debug_realloc(void* ptr, size_t size);

void* oe_debug_memalign(size_t alignment, size_t size);

int oe_debug_posix_memalign(void** memptr, size_t alignment, size_t size);

#endif /* _OE_DEBUG_MALLOC_H */
