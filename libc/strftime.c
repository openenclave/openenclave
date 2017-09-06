#define __OE_NEED_TIME_CALLS
#define _GNU_SOURCE
#include <time.h>
#include <string.h>
#include <stdint.h>
#include <openenclave.h>
#include <oeinternal/calls.h>

size_t strftime(
    char *str, 
    size_t max, 
    const char *format, 
    const struct tm *tm)
{
    size_t ret = 0;
    OE_StrftimeArgs* a = NULL;

    if (!str || !format || !tm)
        goto done;

    if (!(a = OE_HostCalloc(1, sizeof(OE_StrftimeArgs))))
        goto done;

    if (strlcpy(a->format, format, sizeof(a->format)) >= sizeof(a->format))
        goto done;

    memcpy(&a->tm, tm, sizeof(struct tm));

    if (__OE_OCall(OE_FUNC_STRFTIME, (uint64_t)a, NULL) != OE_OK)
        goto done;

    if (strlcpy(str, a->str, max) >= max)
    {
        *str = '\0';
        goto done;
    }

    ret = a->ret;

done:

    if (a)
        OE_HostFree(a);

    return ret;
}

size_t strftime_l(
    char *s,
    size_t max,
    const char *format,
    const struct tm *tm,
    locale_t loc)
{
    return strftime(s, max, format, tm);
}
