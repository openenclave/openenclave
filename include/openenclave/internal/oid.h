// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_OID_H
#define _OE_OID_H

#include <openenclave/bits/defs.h>

OE_EXTERNC_BEGIN

/**
 * OID string representation.
 *
 * OID string representation (e.g., "1.2.3.4"). This structure represents an
 * OID output parameter to prevent buffer length mismatches that the compiler
 * would be unable to detect. For example, consider the following function
 * declaration.
 *
 *     ```
 *     void get_the_oid(char oid[OE_MAX_OID_STRING_SIZE]);
 *     ```
 *
 * This may be called unsafely as follows.
 *
 *     ```
 *     char oid[16];
 *     get_the_oid(oid);
 *     ```
 *
 * Instead, the following definition prevents this coding error.
 *
 *     ```
 *     void get_the_oid(oe_oid_string_t* oid);
 *     ```
 */
typedef struct _oe_oid_string
{
    // Strictly speaking there is no limit on the length of an OID but we chose
    // 128 (the maximum OID length in the SNMP specification). Also, this value
    // is hardcoded to 64 in many implementations.
    char buf[128];
} oe_oid_string_t;

OE_EXTERNC_END

#endif /* _OE_OID_H */
