/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include "sal_unsup.h"

#include <stddef.h>
#include <time.h>
#include <errno.h>

#include "optee.h"
#include <openenclave/host.h>
#include "oeoverintelsgx_u.h"

/* Time-related APIs */

QueryPerformanceCounter_Result ocall_QueryPerformanceCounter(void)
{
    QueryPerformanceCounter_Result result = { 0 };

    result.count = ocall_GetTickCount();
    if (result.count)
        result.status = OE_OK;
    else
        result.status = OE_FAILURE;

    return result;
}

unsigned int ocall_GetTickCount(void)
{
    int r;
    struct timespec ts;
    
    r = clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    if (r)
        return 0;

    return (uint64_t)(ts.tv_nsec / 1000000) + ((uint64_t)ts.tv_sec * 1000ull);
}

uint64_t ocall_time64(void)
{
    return (uint64_t)time(NULL);
}

GetTm_Result ocall_localtime64(uint64_t timer)
{
    GetTm_Result result = { 0 };

    result.err = localtime_r((time_t *)&timer, (struct tm *)&result.tm) == NULL ? EINVAL : 0;

    return result;
}

GetTm_Result ocall_gmtime64(uint64_t timer)
{
    GetTm_Result result = { 0 };
    
    result.err = gmtime_r((time_t *)&timer, (struct tm *)&result.tm) == NULL ? EINVAL : 0;

    return result;
}

/* Process/thread-related APIs */

oe_result_t ocall_exit(int result)
{
    exit(result);
    return OE_OK;
}

oe_result_t oe_acquire_enclave_mutex(_In_ oe_enclave_t *enclave)
{
    struct tcps_optee_context *optee;
    int s;
    
    optee = (struct tcps_optee_context *)enclave;

    s = pthread_mutex_lock(&optee->mutex);

    return s ? OE_FAILURE : OE_OK;
}

void oe_release_enclave_mutex(_In_ oe_enclave_t *enclave)
{
    struct tcps_optee_context *optee;
    
    optee = (struct tcps_optee_context *)enclave;

    pthread_mutex_unlock(&optee->mutex);
}
