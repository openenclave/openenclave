// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/internal/raise.h>

#include "util.h"

oe_result_t oe_util_filetime_to_oe_datetime(
    const FILETIME* filetime,
    oe_datetime_t* datetime)
{
    oe_result_t result = OE_UNEXPECTED;
    SYSTEMTIME systime = {0};
    if (!FileTimeToSystemTime(filetime, &systime))
        OE_RAISE_MSG(
            OE_INVALID_UTC_DATE_TIME,
            "FileTimeToSystemTime failed, err=%#x\n",
            GetLastError());

    datetime->year = systime.wYear;
    datetime->month = systime.wMonth;
    datetime->day = systime.wDay;
    datetime->hours = systime.wHour;
    datetime->minutes = systime.wMinute;
    datetime->seconds = systime.wSecond;

    result = OE_OK;

done:
    return result;
}
