// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#define _GNU_SOURCE
#include <assert.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/time.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

// This definition is replicated from "musl/src/time/__tz.c" as this file has
// some dependencies on other functions which are not developed for the enclave
// environment so we are defining the variable here to resolve the dependency
// of extern variable in gmtime_r.c.
const char __gmt[] = "GMT";

time_t time(time_t* tloc)
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
    oe_gettimeofday_args_t* args = NULL;

    if (!(args = oe_host_calloc(1, sizeof(oe_gettimeofday_args_t))))
        goto done;

    args->ret = -1;

    if (tv)
        args->tv = &args->tvbuf;

    if (tz)
        args->tz = NULL;

    if (oe_ocall(
            OE_FUNC_GETTIMEOFDAY,
            (uint64_t)args,
            NULL,
            OE_OCALL_FLAG_NOT_REENTRANT) != OE_OK)
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
        oe_host_free(args);

    return ret;
}

int clock_gettime(clockid_t clk_id, struct timespec* tp)
{
    size_t ret = -1;
    oe_clock_gettime_args_t* args = NULL;

    if (!(args = oe_host_malloc(sizeof(oe_clock_gettime_args_t))))
        goto done;

    args->ret = -1;
    args->clk_id = clk_id;
    args->tp = tp ? &args->tpbuf : NULL;
    // clockid_t is not available for Windows,
    // So on Windows int32_t is typedef to clockid_t.
    OE_STATIC_ASSERT(sizeof(clockid_t) == sizeof(int32_t));

    if (oe_ocall(
            OE_FUNC_CLOCK_GETTIME,
            (uint64_t)args,
            NULL,
            OE_OCALL_FLAG_NOT_REENTRANT) != OE_OK)
        goto done;

    if (args->ret == 0)
    {
        if (tp)
            memcpy(tp, &args->tpbuf, sizeof(args->tpbuf));
    }

    ret = args->ret;

done:

    if (args)
        oe_host_free(args);

    return ret;
}

int nanosleep(const struct timespec* req, struct timespec* rem)
{
    size_t ret = -1;
    oe_nanosleep_args_t* args = NULL;

    if (!(args = oe_host_calloc(1, sizeof(oe_nanosleep_args_t))))
        goto done;

    args->ret = -1;

    if (req)
    {
        memcpy(&args->reqbuf, req, sizeof(args->reqbuf));
        args->req = &args->reqbuf;
    }

    if (rem)
        args->rem = &args->rembuf;

    if (oe_ocall(
            OE_FUNC_NANOSLEEP,
            (uint64_t)args,
            NULL,
            OE_OCALL_FLAG_NOT_REENTRANT) != OE_OK)
        goto done;

    if (args->ret == 0)
    {
        if (rem)
            memcpy(rem, &args->rembuf, sizeof(args->rembuf));
    }

    ret = args->ret;

done:

    if (args)
        oe_host_free(args);

    return ret;
}
