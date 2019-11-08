// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_HEXDUMP_H
#define _OE_HEXDUMP_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

/**
 * Prints data to host console as hex characters
 *
 * @param data data to be printed
 * @param data_size size in bytes of **data** parameter
 *
 * @return first parameter or NULL if str parameter is too small
 */
void oe_hex_dump(const void* data, size_t size);

/**
 * Converts data to a hexidecimal string
 *
 * @param str hexidecimal string
 * @param str_size size of string buffer (must be at least 2*size+1 bytes)
 * @param data data to be converted
 * @param data_size size in bytes of **data** parameter
 *
 * @return first parameter or NULL if str parameter is too small
 */
char* oe_hex_string(
    char* str,
    size_t str_size,
    const void* data,
    size_t data_size);

OE_EXTERNC_END

#endif /* _OE_HEXDUMP_H */
