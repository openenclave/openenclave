#include <stdio.h>
#include <stdarg.h>
#include <locale.h>
#include <time.h>

#define _PTHREAD_IMPL_H

typedef int nl_item;

char *__nl_langinfo_l(nl_item item, locale_t loc);

char *__nl_langinfo(nl_item item);

struct __pthread_self_return
{
    locale_t locale;
};

static struct __pthread_self_return* __pthread_self(void)
{
    static struct __pthread_self_return ret;
    return &ret;
}

#include "../3rdparty/musl/musl/src/locale/langinfo.c"
