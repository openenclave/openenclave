// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_OID_H
#define _OE_OID_H

#include <openenclave/bits/defs.h>

OE_EXTERNC_BEGIN

typedef struct _oe_oid_string
{
    // Strictly speaking there is no limit on the length of an OID but we chose
    // 128 (the maximum OID length in the SNMP specification). Also, this value
    // is hardcoded to 64 in many implementations.
    char buf[128];
} oe_oid_string_t;

OE_EXTERNC_END

#endif /* _OE_OID_H */
