#define _GNU_SOURCE
#include <stdio.h>
#include <stdarg.h>
#include <assert.h>
#include <string.h>
#include <openenclave/enclave.h>
#include <openenclave/bits/calls.h>
#include <openenclave/bits/print.h>
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
    char *p = buf;
    int n;

    /* Try first with a fixed-length scratch buffer */
    {
        va_list ap;
        va_copy(ap, ap_);
        n = vsnprintf(buf, sizeof(buf), fmt, ap);
        va_end(ap);
    }

    /* If string was truncated, retry with correctly sized buffer */
    if (n >= sizeof(buf))
    {
        if (!(p = alloca(n + 1)))
            return -1;

        va_list ap;
        va_copy(ap, ap_);
        n = vsnprintf(p, n + 1, fmt, ap);
        va_end(ap);
    }

    __OE_HostPrint(p);

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

    if (stream != stdout && stream != stderr)
        return 0;

    memset(buf, 0, sizeof(buf));

    /* ATTN: use heap memory here! */
    va_list ap;
    va_start(ap, fmt);
    n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    __OE_HostPrint(buf);

    return n;
}

OE_WEAK_ALIAS(fprintf, __libcxxrt_fprintf);

size_t __fwritex(const unsigned char *restrict s, size_t l, FILE *restrict f)
{
    return f->write(f, s, l);
}

int __lockfile(FILE *f)
{
    assert("__lockfile() panic" == NULL);
    return 0;
}

void __unlockfile(FILE *f)
{
    assert("__unlockfile() panic" == NULL);
}

int __overflow(FILE *stream, int c)
{
    return c;
}

int getc(FILE *stream)
{
    assert("getc() panic" == NULL);
    return 0;
}

int ungetc(int c, FILE *stream)
{
    assert("ungetc() panic" == NULL);
    return -1;
}

size_t fwrite(
    const void *ptr, size_t size, size_t nmemb, FILE *stream)
{
    /* Only panic if size and nmemb are both non-zero. Otherwise, fwrite() is
     * being called to perform a flush (or in error).
     */
    if ((stream == stdout) || (stream == stderr))
    {
        printf("%.*s", size * nmemb, ptr);
        return nmemb;
    }
    else if (size && nmemb)
    {
        assert("fwrite() panic" == NULL);
    }

    return 0;
}

int fflush(FILE *stream)
{
    return 0;
}

void __stdio_exit(void)
{
    assert("__stdio_exit() panic" == NULL);
}

OE_WEAK_ALIAS(__stdio_exit, __stdio_exit_needed);
