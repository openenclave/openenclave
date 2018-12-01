/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include <assert.h>
#include <stddef.h>

#include <openenclave/enclave.h>
//#include <tcps_time_t.h>
#include "oeinternal_t.h"
#include "../oeoverintelsgx_t.h"

/*
__time64_t _time64(  
   __time64_t *timer)
{
    __time64_t value;
    ocall_time64(&value);
    *timer = value;
    return value;
}
*/

time_t time(time_t *timer)
{
    __time64_t localTime64;
    sgx_status_t status = ocall_time64(&localTime64);

    if (status != SGX_SUCCESS) {
        assert(FALSE);
        return 0;
    }

    if (timer != NULL) {
        *timer = (time_t)localTime64;
    }

    return (time_t)localTime64;
}

__uint32_t GetTickCount()
{
    uint32_t count;
    sgx_status_t status = ocall_GetTickCount(&count);
    if (status != SGX_SUCCESS) {
        assert(FALSE);
        return 0;
    }
    return count;
}

struct tm* _localtime64(const __time64_t *timer)
{
    int host_result;
    static struct ocall_tm tm;

    oe_result_t result = ocall_localtime64(&host_result, *timer, &tm);
    if ((result != OE_OK) || (host_result != 0)) {
        return NULL;
    }

    return (struct tm*)&tm;
}

struct tm* _gmtime64(const __time64_t *timer)
{
    int host_result;
    static struct ocall_tm tm;

    oe_result_t result = ocall_gmtime64(&host_result, *timer, &tm);
    if ((result != OE_OK) || (host_result != 0)) {
        return NULL;
    }
    return (struct tm*)&tm;
}

int QueryPerformanceCounter(uint64_t *count)
{
    oe_result_t host_result;
    oe_result_t result = ocall_QueryPerformanceCounter(&host_result, count);
    if (result != OE_OK) {
        return 0;
    }
    return host_result;
}
