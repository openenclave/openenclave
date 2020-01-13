// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_MUSL_PATCHES_EXECINFO_H
#define _OE_MUSL_PATCHES_EXECINFO_H

#include <openenclave/bits/defs.h>

OE_EXTERNC_BEGIN

// See https://www.gnu.org/software/libc/manual/html_node/Backtraces.html
// for a description of the GNU backtrace functions.

int backtrace(void** buffer, int size);

char** backtrace_symbols(void* const* buffer, int size);

// This is not implemented yet.
// void backtrace_symbols_fd(void *const *buffer, int size, int fd);

OE_EXTERNC_END

#endif /* _OE_MUSL_PATCHES_EXECINFO_H */
