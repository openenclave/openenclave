// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_HEXDUMP_H
#define _OE_HEXDUMP_H

#include <openenclave/defs.h>
#include <openenclave/result.h>
#include <openenclave/types.h>

OE_EXTERNC_BEGIN

/**
 * Prints data to host console as hex characters
 *
 * @param data data to be printed
 * @param dataSize size in bytes of **data** parameter
 *
 * @return first parameter or NULL if str parameter is too small
 */
void OE_HexDump(const void* data, size_t size);

/**
 * Converts data to a hexidecimal string
 *
 * @param str hexidecimal string
 * @param strSize size of string buffer (must be at least 2*size+1 bytes)
 * @param data data to be converted
 * @param dataSize size in bytes of **data** parameter
 *
 * @return first parameter or NULL if str parameter is too small
 */
char* OE_HexString(
    char* str,
    size_t strSize,
    const void* data,
    size_t dataSize);

OE_EXTERNC_END

#endif /* _OE_HEXDUMP_H */
