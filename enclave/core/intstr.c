// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "intstr.h"
#include <openenclave/corelibc/string.h>

const char* oe_uint64_to_hexstr(oe_intstr_buf_t* buf, uint64_t x, size_t* size)
{
    for (size_t i = 0; i < 16; i++)
        buf->data[15 - i] = oe_get_hex_char(x, i);

    buf->data[16] = '\0';

    const char* p = buf->data;

    /* Skip over leading zeros (but not the final zero) */
    while (p[0] && p[1] && p[0] == '0')
        p++;

    if (size)
        *size = oe_strlen(p);

    return p;
}

const char* oe_uint64_to_octstr(oe_intstr_buf_t* buf, uint64_t x, size_t* size)
{
    char* p;
    char* end = buf->data + sizeof(buf->data) - 1;

    p = end;
    *p = '\0';

    do
    {
        *--p = (char)('0' + x % 8);
    } while (x /= 8);

    if (size)
        *size = (size_t)(end - p);

    return p;
}

const char* oe_uint64_to_decstr(oe_intstr_buf_t* buf, uint64_t x, size_t* size)
{
    char* p;
    char* end = buf->data + sizeof(buf->data) - 1;

    p = end;
    *p = '\0';

    do
    {
        *--p = (char)('0' + x % 10);
    } while (x /= 10);

    if (size)
        *size = (size_t)(end - p);

    return p;
}

const char* oe_int64_to_decstr(oe_intstr_buf_t* buf, int64_t x, size_t* size)
{
    char* p;
    int neg = 0;
    static const char _str[] = "-9223372036854775808";
    char* end = buf->data + sizeof(buf->data) - 1;

    if (x == OE_INT64_MIN)
    {
        *size = sizeof(_str) - 1;
        return _str;
    }

    if (x < 0)
    {
        neg = 1;
        x = -x;
    }

    p = end;
    *p = '\0';

    do
    {
        *--p = (char)('0' + x % 10);
    } while (x /= 10);

    if (neg)
        *--p = '-';

    if (size)
        *size = (size_t)(end - p);

    return p;
}
