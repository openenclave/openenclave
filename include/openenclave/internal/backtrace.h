// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_BACKTRACE_H
#define _OE_BACKTRACE_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

/* Maximum backtrace size */
#define OE_BACKTRACE_MAX 32

/**
 * This function is intended to be called by GNU **backtrace** and
 * **oe_backtrace** functions.
 */
int oe_backtrace_impl(void** start_frame, void** buffer, int size);

/**
 * This function implements GNU **backtrace_symbols** and
 * **oe_backtrace** functions. The debug_malloc feature gathers backtraces when
 * memory is allocated. debug-malloc itself must not be used to allocate symbol
 * buffer in this case. This internal function debug-malloc to use the lower
 * level dlmalloc functions for creating backtrace symbols.
 */
char** oe_backtrace_symbols_impl(
    void* const* buffer,
    int size,
    void* (*malloc_fcn)(size_t),
    void* (*realloc_fcn)(void*, size_t),
    void (*free_fcn)(void*));

/**
 * This function behaves like the GNU **backtrace** function. See the
 * **backtrace** manpage for more information.
 */
int oe_backtrace(void** buffer, int size);

/**
 * This function behaves like the GNU **backtrace_symbols** function. See the
 * **backtrace_symbols** manpage for more information. The return value must
 * released with oe_backtrace_symbols_free().
 */
char** oe_backtrace_symbols(void* const* buffer, int size);

/**
 * Free a buffer obtained with **oe_backtrace_symbols()**.
 */
void oe_backtrace_symbols_free(char** ptr);

/**
 * Print a backtrace for the current function.
 */
oe_result_t oe_print_backtrace(void);

OE_EXTERNC_END

#endif /* _OE_BACKTRACE_H */
