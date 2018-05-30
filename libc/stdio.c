// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.


#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif

#include <assert.h>
#include <openenclave/bits/calls.h>
#include <openenclave/bits/enclavelibc.h>
#include <openenclave/bits/print.h>
#include <openenclave/enclave.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include "../3rdparty/musl/musl/src/internal/stdio_impl.h"

FILE* const stdin = ((FILE*)0x10000000);
FILE* const stdout = ((FILE*)0x20000000);
FILE* const stderr = ((FILE*)0x30000000);

int puts(const char* str)
{
    return __OE_HostPuts(str);
}

int putchar(int c)
{
    return __OE_HostPutchar(c);
}

int vprintf(const char* fmt, va_list ap_)
{
    char buf[256];
    char* p = buf;
    int n;

    /* Try first with a fixed-length scratch buffer */
    {
        va_list ap;
        va_copy(ap, ap_);
        n = vsnprintf(buf, sizeof(buf), fmt, ap);
        va_end(ap);
    }

    if (n < 0)
        return n;

    /* If string was truncated, retry with correctly sized buffer */
    if ((size_t)n >= sizeof(buf))
    {
        if (!(p = (char*)alloca(n + 1)))
            return -1;

        va_list ap;
        va_copy(ap, ap_);
        n = vsnprintf(p, n + 1, fmt, ap);
        va_end(ap);
    }

    __OE_HostPrint(0, p, (size_t)-1);

    return n;
}

int printf(const char* fmt, ...)
{
    int n;

    va_list ap;
    va_start(ap, fmt);
    n = vprintf(fmt, ap);
    va_end(ap);

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

    if (n < 0)
        return n;

    buf[sizeof(buf) - 1] = 0;

    if ((size_t)n > sizeof(buf))
        n = sizeof(buf);

    __OE_HostPrint(device, buf, n);

    return n;
}

OE_WEAK_ALIAS(fprintf, __libcxxrt_fprintf);

size_t __fwritex(const unsigned char* s, size_t l, FILE* f)
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
        __OE_HostPrint(0, (const char*)ptr, size * nmemb);
        return nmemb;
    }
    else if (stream == stderr)
    {
        /* Write to standard error device */
        __OE_HostPrint(1, (const char*)ptr, size * nmemb);
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

void __stdio_exit_needed(void)
{
    __stdio_exit();
}
