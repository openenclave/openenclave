/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include <stddef.h>

#include <tee_api.h>
#include <tcps_time_t.h>
#include "oeinternal_t.h"

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
    int err;
    static struct tm tm;
    oe_result_t result = ocall_localtime64(&err, *timer, (ocall_tm*)&tm);
    if (result != OE_OK) {
        return NULL;
    }

    return (err != 0) ? NULL : (struct tm*)&tm;
}

struct tm* _gmtime64(const __time64_t *timer)
{
    int err;
    static struct tm tm;
    oe_result_t result = ocall_gmtime64(&err, *timer, (ocall_tm*)&tm);
    if (result != OE_OK) {
        return NULL;
    }

    return (err != 0) ? NULL : (struct tm*)&tm;
}

struct tm* gmtime(const time_t *timer)
{
    __time64_t timer64 = *timer;

    return _gmtime64(&timer64);
}
