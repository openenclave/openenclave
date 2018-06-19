// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/enclavelibc.h>
#include <openenclave/internal/print.h>
#include "voprintf.h"

typedef struct _oe_out_str
{
    oe_out_t base;
    char* str;
    size_t size;
    size_t off;
}
oe_out_str_t;

static ssize_t _write(oe_out_t* out_, const void* buf, size_t count)
{
    oe_out_str_t* out = (oe_out_str_t*)out_;

    if (out->off < out->size)
    {
        /* Leave an extra byte for the zero-terminator */
        size_t rem = out->size - out->off - 1;
        size_t n;

        if (rem < count)
            n = rem;
        else
            n = count;

        oe_memcpy(&out->str[out->off], buf, n);
        out->str[out->off + n] = '\0';
    }

    out->off += count;

    return count;
}

static void _oe_out_str_init(oe_out_str_t* out, char* str, size_t size)
{
    out->base.write = _write;
    out->str = str;
    out->size = size;
    out->off = 0;
}

int oe_vsnprintf(char* str, size_t size, const char* fmt, oe_va_list ap)
{
    oe_out_str_t out;

    if (!str && size != 0)
        return -1;

    _oe_out_str_init(&out, str, size);

    return oe_voprintf(&out.base, fmt, ap);
}

int oe_snprintf(char* str, size_t size, const char* fmt, ...)
{
    oe_va_list ap;
    oe_va_start(ap, fmt);
    int n = oe_vsnprintf(str, size, fmt, ap);
    oe_va_end(ap);
    return n;
}

int oe_vprintf(const char* fmt, oe_va_list ap_)
{
    char buf[256];
    char* p = buf;
    int n;

    /* Try first with a fixed-length scratch buffer */
    {
        oe_va_list ap;
        oe_va_copy(ap, ap_);
        n = oe_vsnprintf(buf, sizeof(buf), fmt, ap);
        oe_va_end(ap);

        if (n < sizeof(buf))
        {
            __oe_host_print(0, p, (size_t)-1);
            goto done;
        }
    }

    /* If string was truncated, retry with correctly sized buffer */
    {
        char new_buf[n + 1];
        p = new_buf;

        oe_va_list ap;
        oe_va_copy(ap, ap_);
        n = oe_vsnprintf(p, n + 1, fmt, ap);
        oe_va_end(ap);

        __oe_host_print(0, p, (size_t)-1);
    }

done:
    return n;
}
