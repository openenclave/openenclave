#include <sys/time.h>
#include <time.h>
#include <assert.h>
#include <string.h>
#include <openenclave.h>
#define __OE_NEED_TIME_CALLS
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

#if 0
int gettimeofday(struct timeval* tv, struct timezone* tz)
#else
int gettimeofday(struct timeval* tv, void* tz)
#endif
{
    size_t ret = -1;
    OE_GettimeofdayArgs* args = NULL;

    if (!(args = OE_HostCalloc(1, sizeof(OE_GettimeofdayArgs))))
        goto done;

    args->ret = -1;

    if (tv)
        args->tv = &args->tvbuf;

    if (tz)
        args->tz = NULL;

    if (__OE_OCall(OE_FUNC_GETTIMEOFDAY, (oe_uint64_t)args, NULL) != OE_OK)
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
        OE_HostFree(args);

    return ret;
}

int clock_gettime(clockid_t clk_id, struct timespec *tp)
{
    size_t ret = -1;
    OE_ClockgettimeArgs* args = NULL;

    if (!(args = OE_HostMalloc(sizeof(OE_ClockgettimeArgs))))
        goto done;

    args->ret = -1;
    args->tp = tp ? &args->tpbuf : NULL;

    if (__OE_OCall(OE_FUNC_CLOCK_GETTIME, (oe_uint64_t)args, NULL) != OE_OK)
        goto done;

    if (args->ret == 0)
    {
        if (tp)
            memcpy(tp, &args->tpbuf, sizeof(args->tpbuf));
    }

    ret = args->ret;

done:

    if (args)
        OE_HostFree(args);

    return ret;
}
