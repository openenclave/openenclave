#include <stdio.h>
#include <stdarg.h>
#include <locale.h>
#include <time.h>

#define _PTHREAD_IMPL_H

typedef int nl_item;

const char *__strftime_fmt_1(
    char (*s)[100], size_t *l, int f, const struct tm *tm, locale_t loc);

struct __pthread_self_return
{
    locale_t locale;
};

static struct __pthread_self_return* __pthread_self(void)
{
    static struct __pthread_self_return ret;
    return &ret;
}

#include "../3rdparty/musl/musl/src/time/strftime.c"
