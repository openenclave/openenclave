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
