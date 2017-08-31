#include <sys/time.h>
#include <time.h>
#include <assert.h>
#include <openenclave.h>
#include <oeinternal/calls.h>

time_t time(time_t *tloc)
{
    struct timeval tv;

    if (gettimeofday(&tv, NULL) != 0)
        return (time_t)-1;

    if (tloc)
        *tloc = tv.tv_sec;

    return tv.tv_sec;
}

int gettimeofday(struct timeval* tv, struct timezone* tz)
{
    size_t ret = -1;
    OE_GettimeofdayArgs* args = NULL;

    if (!(args = calloc_u(1, sizeof(OE_GettimeofdayArgs))))
        goto done;

    args->ret = -1;

    if (tv)
        args->tv = &args->tvbuf;

    if (tz)
        args->tz = &args->tzbuf;

    if (__OE_OCall(OE_FUNC_GETTIMEOFDAY, (uint64_t)args, NULL) != OE_OK)
        goto done;

    if (args->ret == 0)
    {
        if (tv)
            memcpy(tv, &args->tvbuf, sizeof(args->tvbuf));

        if (tz)
            memcpy(tz, &args->tzbuf, sizeof(args->tzbuf));
    }

    ret = args->ret;

done:

    if (args)
        free_u(args);

    return ret;
}

int clock_gettime(clockid_t clk_id, struct timespec *tp)
{
    size_t ret = -1;
    OE_ClockgettimeArgs* args = NULL;

    if (!(args = malloc_u(sizeof(OE_ClockgettimeArgs))))
        goto done;

    args->ret = -1;
    args->tp = tp ? &args->tpbuf : NULL;

    if (__OE_OCall(OE_FUNC_CLOCK_GETTIME, (uint64_t)args, NULL) != OE_OK)
        goto done;

    if (args->ret == 0)
    {
        if (tp)
            memcpy(tp, &args->tpbuf, sizeof(args->tpbuf));
    }

    ret = args->ret;

done:

    if (args)
        free_u(args);

    return ret;
}
