// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_MALLOC_H
#define _OE_MALLOC_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

typedef void (*oe_allocation_failure_callback_t)(
    const char* file,
    size_t line,
    const char* func,
    size_t size);

void oe_set_allocation_failure_callback(
    oe_allocation_failure_callback_t function);

/* Dump the list of all in-use allocations */
void oe_debug_malloc_dump(void);

/* Print trace of memory still in use. Return number of blocks allocated. */
size_t oe_debug_malloc_check(void);

//
// If true, oe_debug_malloc_check() is not called on enclave termination.
// To use this mechanism in an enclave:
//
//     #include <openenclave/internal/malloc.h>
//     .
//     .
//     .
//     oe_disable_debug_malloc_check = true;
//
// The variable must be set prior to enclave termination so it is best to
// set it as soon as the enclave is entered.
//
extern bool oe_disable_debug_malloc_check;

OE_EXTERNC_END

#endif /* _OE_MALLOC_H */
