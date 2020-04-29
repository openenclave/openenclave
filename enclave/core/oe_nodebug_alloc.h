// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_NODEBUG_ALLOC_H
#define _OE_NODEBUG_ALLOC_H

#include <openenclave/bits/defs.h>
#include <openenclave/corelibc/stddef.h>

OE_EXTERNC_BEGIN

// A small number of places want to use the underlying allocator
// without the debug shim on top, hence those explicit symbols.
void* oe_nodebug_malloc(size_t s);
void oe_nodebug_free(void* ptr);
void* oe_nodebug_realloc(void* ptr, size_t s);
void* oe_nodebug_memalign(size_t alignment, size_t size);

OE_EXTERNC_END

#endif /* _OE_NODEBUG_ALLOC_H */
