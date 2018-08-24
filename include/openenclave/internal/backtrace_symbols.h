// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_BACKTRACE_SYMBOLS_H
#define _OE_BACKTRACE_SYMBOLS_H

#include <openenclave/host.h>

OE_EXTERNC_BEGIN

/**
 * This function behaves like the GNU **backtrace_symbols** function, except
 * it requires an enclave parameter. See the **backtrace_symbols** manpage for
 * more information.
 */
char** oe_backtrace_symbols(
    oe_enclave_t* enclave,
    void* const* buffer,
    int size);

OE_EXTERNC_END

#endif /* _OE_BACKTRACE_SYMBOLS_H */
