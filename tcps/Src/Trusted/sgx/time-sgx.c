/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include <assert.h>
#include <stddef.h>

#include <tcps_time_t.h>
#include "../TcpsCalls_t.h"

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
    static GetTm_Result result;

    sgx_status_t status = ocall_localtime64(&result, *timer);
    if ((status != SGX_SUCCESS) || (result.err != 0)) {
        return NULL;
    }

    return (struct tm*)&result.tm;
}

struct tm* _gmtime64(const __time64_t *timer)
{
    static GetTm_Result result;

    sgx_status_t status = ocall_gmtime64(&result, *timer);
    if ((status != SGX_SUCCESS) || (result.err != 0)) {
        return NULL;
    }
    return (struct tm*)&result.tm;
}

int QueryPerformanceCounter(uint64_t *count)
{
    QueryPerformanceCounter_Result result;
    sgx_status_t status = ocall_QueryPerformanceCounter(&result);
    if (status != SGX_SUCCESS) {
        return 0;
    }
    *count = result.count;
    return result.status;
}
