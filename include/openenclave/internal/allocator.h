// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef OE_ADVANCED_ALLOCATOR_H
#define OE_ADVANCED_ALLOCATOR_H

#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

void oe_allocator_init(void* heap_start_address, void* heap_end_address);
void oe_allocator_cleanup(void);

void oe_allocator_thread_init(void);
void oe_allocator_thread_cleanup(void);

void* oe_allocator_malloc(size_t size);
void oe_allocator_free(void* ptr);
void* oe_allocator_calloc(size_t nmemb, size_t size);
void* oe_allocator_realloc(void* ptr, size_t size);
void* oe_allocator_aligned_alloc(size_t alignment, size_t size);
int oe_allocator_posix_memalign(void** memptr, size_t alignment, size_t size);
size_t oe_allocator_malloc_usable_size(void* ptr);

OE_EXTERNC_END

#endif // OE_ADVANCED_ALLOCATOR_H
