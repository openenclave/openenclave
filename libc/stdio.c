// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#define _GNU_SOURCE
#include <assert.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/enclavelibc.h>
#include <openenclave/internal/print.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include "../3rdparty/musl/musl/src/internal/stdio_impl.h"

FILE* const stdin = ((FILE*)0x1000000000000001);
FILE* const stdout = ((FILE*)0x1000000000000002);
FILE* const stderr = ((FILE*)0x1000000000000003);

int puts(const char* str)
{
    return __oe_host_puts(str);
}

int putchar(int c)
{
    return __oe_host_putchar(c);
}

int vprintf(const char* fmt, va_list ap)
{
    return oe_vprintf(fmt, ap);
}

int printf(const char* fmt, ...)
{
    int n;

    oe_va_list ap;
    oe_va_start(ap, fmt);
    n = oe_vprintf(fmt, ap);
    oe_va_end(ap);

    return n;
}

OE_WEAK_ALIAS(printf, __libcxxrt_printf);

int fprintf(FILE* stream, const char* fmt, ...)
{
    char buf[1024];
    int n;
    int device;

    if (stream == stdout)
        device = 0;
    else if (stream == stderr)
        device = 1;
    else
    {
        va_list ap;
        va_start(ap, fmt);
        int r = vfprintf(stream, fmt, ap);
        va_end(ap);
        return r;
    }

    {
        va_list ap;
        va_start(ap, fmt);
        n = vsnprintf(buf, sizeof(buf), fmt, ap);
        va_end(ap);
    }

    buf[sizeof(buf) - 1] = 0;
    if (n > sizeof(buf))
        n = sizeof(buf);
    __oe_host_print(device, buf, n);
    return n;
}

OE_WEAK_ALIAS(fprintf, __libcxxrt_fprintf);

size_t __fwritex(const unsigned char* restrict s, size_t l, FILE* restrict f)
{
    return f->write(f, s, l);
}

int __lockfile(FILE* f)
{
    assert("__lockfile() panic" == NULL);
    return 0;
}

void __unlockfile(FILE* f)
{
    assert("__unlockfile() panic" == NULL);
}

int __overflow(FILE* stream, int c)
{
    return c;
}

int getc(FILE* stream)
{
    assert("getc() panic" == NULL);
    return 0;
}

int ungetc(int c, FILE* stream)
{
    assert("ungetc() panic" == NULL);
    return -1;
}

size_t fwrite(const void* ptr, size_t size, size_t nmemb, FILE* stream)
{
    if (stream == stdout)
    {
        /* Write to standard output device */
        __oe_host_print(0, ptr, size * nmemb);
        return nmemb;
    }
    else if (stream == stderr)
    {
        /* Write to standard error device */
        __oe_host_print(1, ptr, size * nmemb);
        return nmemb;
    }
    else if (size && nmemb)
    {
        /* Only panic if size and nmemb are both non-zero */
        assert("fwrite() panic" == NULL);
    }

    return 0;
}

int fflush(FILE* stream)
{
    return 0;
}

void __stdio_exit(void)
{
    assert("__stdio_exit() panic" == NULL);
}

OE_WEAK_ALIAS(__stdio_exit, __stdio_exit_needed);
