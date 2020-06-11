// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_TLS_H
#define _OE_TLS_H

#include <openenclave/bits/types.h>

/*
**==============================================================================
**
** This file defines types and accessors for thread-local-storage variables.
** Liboecore avoids use of the __thread storage modifier, which allows
** third-party runtimes to take over and manage the TLS region without
** conflicting with liboecore. One example is an application that brings
** its own C runtime, which tend to manage the TLS region.
**
**==============================================================================
*/

OE_EXTERNC_BEGIN

/* This structure manages a pool of shared memory (memory visible to both
 * the enclave and the host). An instance of this structure is maintained
 * for each thread. This structure is used in enclave/core/arena.c.
 */
typedef struct _oe_shared_memory_arena_t
{
    uint8_t* buffer;
    uint64_t capacity;
    uint64_t used;
} oe_shared_memory_arena_t;

oe_shared_memory_arena_t* oe_get_shared_memory_arena_tls(void);

int* oe_get_errno_address_tls(void);

OE_EXTERNC_END

#endif // _OE_TLS_H
