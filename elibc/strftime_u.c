#include <time.h>
#include <openenclave.h>
#include <__openenclave/calls.h>

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

    if (!(a = calloc_u(1, sizeof(OE_StrftimeArgs))))
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
        free_u(a);

    return ret;
}
