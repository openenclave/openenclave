#include <stdio.h>
#include <stdarg.h>
#include <openenclave.h>
#include <oeinternal/calls.h>
#include "../3rdparty/musl/musl/src/internal/stdio_impl.h"

FILE* stdin = ((FILE*)0x10000000);
FILE* stdout = ((FILE*)0x20000000);
FILE* stderr = ((FILE*)0x30000000);

int puts_u(const char* str)
{
    int ret = EOF;
    char* hstr = NULL;

    if (!str)
        goto done;

    if (!(hstr = strdup_u(str)))
        goto done;

    if (__OE_OCall(OE_FUNC_PUTS, (uint64_t)hstr, NULL) != OE_OK)
        goto done;

done:

    if (hstr)
        free_u(hstr);

    return ret;
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

int printf_u(const char* fmt, ...)
{
    char buf[1024];
    int n;

    memset(buf, 0, sizeof(buf));

    /* ATTN: use heap memory here! */
    va_list ap;
    va_start(ap, fmt);
    n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    puts_u(buf);

    return n;
}

/* ATTN: this function is not reached when called */
int fprintf_u(FILE* stream, const char* fmt, ...)
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

    puts_u(buf);

    return n;
}

__WEAK_ALIAS(fprintf_u, fprintf);

size_t __fwritex(const unsigned char *restrict s, size_t l, FILE *restrict f)
{
    return f->write(f, s, l);
}

int __lockfile(FILE *f)
{
    puts_u("__lockfile() not implemented\n");
    abort();
    return 0;
}

void __unlockfile(FILE *f)
{
    puts_u("__unlockfile() not implemented\n");
    abort();
}

int __overflow(FILE *stream, int c)
{
    return c;
}
