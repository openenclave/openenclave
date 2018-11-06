/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#pragma once
#ifndef TRUSTED_CODE
# error tcps_time_t.h should only be included with TRUSTED_CODE
#endif
#include "oeenclave.h"

#include <openenclave/bits/timetypes.h>

#ifndef _INC_TIME
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

#ifdef USE_OPTEE
# include <optee/tcps_time_optee_t.h>
#endif
