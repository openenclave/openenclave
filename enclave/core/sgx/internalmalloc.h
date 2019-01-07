// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

void* _oe_malloc(size_t);
void  _oe_free(void*);
void* _oe_calloc(size_t, size_t);
void* _oe_realloc(void*, size_t);
void* _oe_memalign(size_t alignment, size_t size);
int   _oe_posix_memalign(void** memptr, size_t alignment, size_t size);

void _oe_alloc_thread_teardown();
void _oe_alloc_thread_startup();