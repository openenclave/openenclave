#define __OE_NEED_TIME_CALLS
#include <openenclave/enclave.h>
#include <openenclave/internal/enclavelibc.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/malloc.h>
#include <openenclave/internal/random.h>
#include "../3rdparty/mbedtls/include/bits/mbedtls_libc.h"

time_t oe_time(time_t* tloc)
{
    time_t ret = 0;
    oe_gettimeofday_args_t* args = NULL;
    const uint64_t flags = OE_OCALL_FLAG_NOT_REENTRANT;

    if (!(args = oe_host_calloc(1, sizeof(oe_gettimeofday_args_t))))
        goto done;

    args->ret = -1;
    args->tv = &args->tvbuf;
    args->tz = NULL;

    if (oe_ocall(OE_FUNC_GETTIMEOFDAY, (uint64_t)args, NULL, flags) != OE_OK)
    {
        oe_assert("panic" == NULL);
        goto done;
    }

    if (args->ret != 0)
    {
        oe_assert("panic" == NULL);
        goto done;
    }

    ret = args->tvbuf.tv_sec;

    if (tloc)
        *tloc = ret;

done:

    if (args)
        oe_host_free(args);

    return ret;
}

struct oe_tm* oe_gmtime(const oe_time_t* timep)
{
    extern int __secs_to_tm(long long t, struct tm *tm);
    static struct tm _tm;

    if (!timep || __secs_to_tm(*timep, &_tm) != 0)
    {
        oe_assert("panic" == NULL);
        return NULL;
    }

    return (struct oe_tm*)&_tm;
}
