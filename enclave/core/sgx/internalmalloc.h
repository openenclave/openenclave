// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// The following functions directly call the allocator, bypassing
// error processing and the debug allocator wrapper.  They should only be used
// in exceptional circumstances.
void* oe_internal_malloc(size_t);
void  oe_internal_free(void*);
void* oe_internal_calloc(size_t, size_t);
void* oe_internal_realloc(void*, size_t);
void* oe_internal_memalign(size_t alignment, size_t size);
int   oe_internal_posix_memalign(void** memptr, size_t alignment, size_t size);

void oe_alloc_thread_teardown();
void oe_alloc_thread_startup();
