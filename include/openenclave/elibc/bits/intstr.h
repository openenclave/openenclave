// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_INTSTR_H
#define _OE_INTSTR_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

/* Get hex character of i-th nibble, where 0 is the least significant nibble */
OE_INLINE char oe_get_hex_char(uint64_t x, size_t i)
{
    uint64_t nbits = (uint64_t)i * 4;
    char nibble = (char)((x & (0x000000000000000fUL << nbits)) >> nbits);
    return ((nibble < 10) ? ('0' + nibble) : ('a' + (nibble - 10)));
}

typedef struct _oe_intstr_buf
{
    char data[32];
} oe_intstr_buf_t;

const char* oe_uint64_to_hexstr(oe_intstr_buf_t* buf, uint64_t x, size_t* size);

const char* oe_uint64_to_octstr(oe_intstr_buf_t* buf, uint64_t x, size_t* size);

const char* oe_uint64_to_decstr(oe_intstr_buf_t* buf, uint64_t x, size_t* size);

const char* oe_int64_to_decstr(oe_intstr_buf_t* buf, int64_t x, size_t* size);

OE_EXTERNC_END

#endif /* _OE_INTSTR_H */
