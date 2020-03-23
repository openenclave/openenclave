// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_ALLOC_THREAD_H
#define _OE_ALLOC_THREAD_H

#include <openenclave/bits/defs.h>

OE_EXTERNC_BEGIN

// Thread-specific startup and teardown calls for the memory allocator
void oe_alloc_thread_startup();
void oe_alloc_thread_teardown();

OE_EXTERNC_END

#endif /* _OE_ALLOC_THREAD_H */
