// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_INTSTR_H
#define _OE_INTSTR_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>

OE_EXTERNC_BEGIN

typedef struct _oe_intstr_buf
{
    char data[32];
}
oe_intstr_buf_t;

const char* oe_uint64_to_hexstr(oe_intstr_buf_t* buf, uint64_t x, size_t* size);

const char* oe_uint64_to_octstr(oe_intstr_buf_t* buf, uint64_t x, size_t* size);

const char* oe_uint64_to_decstr(oe_intstr_buf_t* buf, uint64_t x, size_t* size);

const char* oe_int64_to_decstr(oe_intstr_buf_t* buf, int64_t x, size_t* size);

OE_EXTERNC_END

#endif /* _OE_INTSTR_H */
