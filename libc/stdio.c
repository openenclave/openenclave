#define _GNU_SOURCE
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <openenclave.h>
#include <oeinternal/calls.h>
#include "../3rdparty/musl/musl/src/internal/stdio_impl.h"

FILE* const stdin = ((FILE*)0x10000000);
FILE* const stdout = ((FILE*)0x20000000);
FILE* const stderr = ((FILE*)0x30000000);

int puts(const char* str)
{
    return OE_HostPuts(str);
}

int putchar(int c)
{
    return OE_HostPutchar(c);
}

int asprintf(char **strp, const char *fmt, ...)
{
    if (!strp)
        return 0;

    if (!(*strp = malloc(4096)))
        return 0;

    va_list ap;
    va_start(ap, fmt);
    int n = vasprintf(strp, fmt, ap);
    va_end(ap);
    return n;
}

int printf(const char* fmt, ...)
{
    char buf[1024];
    int n;

    memset(buf, 0, sizeof(buf));

    /* ATTN: use heap memory here! */
    va_list ap;
    va_start(ap, fmt);
    n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    puts(buf);

    return n;
}

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

    puts(buf);

    return n;
}

size_t __fwritex(const unsigned char *restrict s, size_t l, FILE *restrict f)
{
    return f->write(f, s, l);
}

int __lockfile(FILE *f)
{
    puts("__lockfile() not implemented\n");
    abort();
    return 0;
}

void __unlockfile(FILE *f)
{
    puts("__unlockfile() not implemented\n");
    abort();
}

int __overflow(FILE *stream, int c)
{
    return c;
}

int getc(FILE *stream)
{
    puts("getc() not implemented\n");
    abort();
}

int ungetc(int c, FILE *stream)
{
    puts("ungetc() not implemented\n");
    abort();
}

size_t fwrite(
    const void *ptr, size_t size, size_t nmemb, FILE *stream)
{
    puts("fwrite() not implemented\n");
    abort();
}

int fflush(FILE *stream)
{
    return 0;
}
