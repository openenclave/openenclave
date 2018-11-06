/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include <stddef.h>

#include <tcps_string_t.h>
#include <tcps_time_t.h>
#include <TcpsCalls_t.h>

__time64_t _time64(
    __time64_t *timer)
{
    /* TEE_GetSystemTime has an arbitrary origin, but TEE_GetREETime gets the
     * number of seconds since 1970, just like time() does.
     */
    TEE_Time value;
    TEE_GetREETime(&value);
    
    if (timer != NULL) {
        *timer = value.seconds;
    }

    return value.seconds;
}

time_t time(
    time_t *timer)
{
    __time64_t t;
    _time64(&t);
    
    if (timer != NULL) {
        *timer = t;
    }

    return t;
}

uint32_t GetTickCount(void)
{
    uint32_t count;
    TEE_Time value;

    /* TEE_GetSystemTime gets the number of seconds and milliseconds since 1970, just like time() does. */
    TEE_GetSystemTime(&value);
    count = ((value.seconds * 1000) + value.millis);
    return count;
}

struct tm* _localtime64(const __time64_t *timer)
{
    GetTm_Result result;
    static struct tm tm;
    sgx_status_t sgxStatus;

Tcps_InitializeStatus(Tcps_Module_Helper_t, "_localtime64");

    sgxStatus = ocall_localtime64(&result, *timer);
    Tcps_GotoErrorIfTrue(sgxStatus != SGX_SUCCESS, Tcps_Bad);
    uStatus = result.err;
    Tcps_GotoErrorIfBad(uStatus);
    memcpy(&tm, &result.tm, sizeof(tm));

    return (struct tm*)&tm;

Tcps_BeginErrorHandling;
    return NULL;
}

struct tm* _gmtime64(const __time64_t *timer)
{
    GetTm_Result result;
    sgx_status_t sgxStatus;
    static struct tm tm;

Tcps_InitializeStatus(Tcps_Module_Helper_t, "_gmtime64");

    sgxStatus = ocall_gmtime64(&result, *timer);
    Tcps_GotoErrorIfTrue(sgxStatus != SGX_SUCCESS, Tcps_Bad);
    uStatus = result.err;
    Tcps_GotoErrorIfBad(uStatus);
    memcpy(&tm, &result.tm, sizeof(tm));

    return (struct tm*)&tm;

Tcps_BeginErrorHandling;
    return NULL;
}

struct tm* gmtime(const time_t *timer)
{
    __time64_t timer64 = *timer;

    return _gmtime64(&timer64);
}
