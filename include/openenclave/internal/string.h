// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

/**
 * @file string.h
 *
 * This file defines non-standard functions for manipulating strings. Standard
 * C string functions are defined in <openenclave/internal/enclavelibc.h>.
 *
 */

#ifndef _OE_STRING_H
#define _OE_STRING_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>

/**
 * Substitutes occurences of **pattern** with **replacement**.
 *
 * @param str the string buffer.
 * @param size the size of the string buffer.
 * @param pattern the pattern string to be replaced.
 * @param replacement the replacement string.
 *
 * @returns the size of the resulting string including the zero terminator or 
 *     (size_t)-1 if a parameter is invalid. If this value is greater or equal 
 *     to **size**, then either a parameter is invalid (-1) or the string 
 *     buffer is too small to hold the result.
 */
size_t oe_string_substitute(
    char* str,
    size_t size,
    const char* pattern,
    const char* replacement);

size_t oe_string_insert(
    char* str,
    size_t size,
    size_t pos,
    const char* insert);

#endif /* _OE_STRING_H */
