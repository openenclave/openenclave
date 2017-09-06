#define _GNU_SOURCE
#include <pthread.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <assert.h>
#include <dlfcn.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-prototypes"

int __libcxxrt_dladdr(void *addr, Dl_info *info)
{
    assert("__libcxxrt_dladdr(): panic" == NULL);
    return -1;
}

int __libcxxrt_sched_yield(void)
{
    assert("__libcxxrt_sched_yield(): panic" == NULL);
    return -1;
}

int __libcxxrt_fprintf(FILE* stream, const char* fmt, ...)
{
    char buf[1024];
    int n;

    memset(buf, 0, sizeof(buf));

    va_list ap;
    va_start(ap, fmt);
    n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    puts(buf);

    return n;
}

int __libcxxrt_printf(const char* fmt, ...)
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
