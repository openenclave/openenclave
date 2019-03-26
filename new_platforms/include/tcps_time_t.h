/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#pragma once
#ifndef _OE_ENCLAVE_H
# include <openenclave/enclave.h>
#endif

#include <openenclave/bits/timetypes.h>

#if !defined(OE_USE_OPTEE) && !defined(_INC_TIME)
/* Only include these definitions if not already included by time.h */

__time64_t _time64(
    __time64_t *timer);

time_t time(
    time_t *timer);

struct tm *gmtime(const time_t *timer);

struct tm *gmtime_r(const time_t *timep, struct tm *result);

struct tm* _gmtime64(const __time64_t *timer);

struct tm *localtime(const time_t *timer);

struct tm *_localtime64(const __time64_t *timer);

#endif

// #ifdef OE_USE_OPTEE
// # include <optee/time_optee_t.h>
// #endif
