#define __OE_NEED_TIME_CALLS
#include <time.h>
#include <string.h>
#include <openenclave.h>
#include <oeinternal/calls.h>

int nanosleep(const struct timespec *req, struct timespec *rem)
{
    size_t ret = -1;
    OE_NanosleepArgs* args = NULL;

    if (!(args = OE_HostCalloc(1, sizeof(OE_NanosleepArgs))))
        goto done;

    args->ret = -1;

    if (req)
    {
        memcpy(&args->reqbuf, req, sizeof(args->reqbuf));
        args->req = &args->reqbuf;
    }

    if (rem)
        args->rem = &args->rembuf;

    if (__OE_OCall(OE_FUNC_NANOSLEEP, (uint64_t)args, NULL) != OE_OK)
        goto done;

    if (args->ret == 0)
    {
        if (rem)
            memcpy(rem, &args->rembuf, sizeof(args->rembuf));
    }

    ret = args->ret;

done:

    if (args)
        OE_HostFree(args);

    return ret;
}
