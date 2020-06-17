// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_INTERNAL_ARGV_H
#define _OE_INTERNAL_ARGV_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

/* Convert an argv[] array into a flat buffer. */
oe_result_t oe_buffer_to_argv(
    const void* buf,
    size_t buf_size,
    char*** argv_out,
    size_t argc,
    void* (*malloc_func)(size_t),
    void (*free_func)(void*));

/* Convert a buffer into an argv[] array with a null argv[argc] entry. */
oe_result_t oe_argv_to_buffer(
    const char* argv[],
    size_t argc,
    void* buf_out,
    size_t buf_size,
    size_t* buf_size_out);

OE_EXTERNC_END

#endif /* _OE_INTERNAL_ARGV_H */
