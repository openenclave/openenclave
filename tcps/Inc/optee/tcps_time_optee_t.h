/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#pragma once
#ifndef TRUSTED_CODE
# error tcps_time_optee_t.h should only be included with TRUSTED_CODE
#endif
#ifndef USE_OPTEE
# error tcps_time_optee_t.h should only be included with USE_OPTEE
#endif
#include "tcps_t.h"

#ifndef _TM_DEFINED
#define _TM_DEFINED
struct tm {
    int tm_sec;
    int tm_min;
    int tm_hour;
    int tm_mday;
    int tm_mon;
    int tm_year;
    int tm_wday;
    int tm_yday;
    int tm_isdst;
};
#endif
