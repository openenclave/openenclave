// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/bits/defs.h>
#include <openenclave/internal/datetime.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/time.h>
#include <time.h>

#define UNIX_EPOCH_YEAR (1970)
#define OE_DATETIME_STR_SIZE (21)

oe_result_t oe_datetime_is_valid(const oe_datetime_t* datetime)
{
    oe_result_t result = OE_FAILURE;
    bool is_leap_year = false;
    bool valid_day = false;
    uint32_t day = 0;

    if (datetime == NULL)
        OE_RAISE(OE_INVALID_PARAMETER);

    // Validate the datetime.
    // Check against unix epoch time (Jan 1, 1970)
    if (datetime->year < UNIX_EPOCH_YEAR)
        OE_RAISE(OE_INVALID_UTC_DATE_TIME);

    // Check month and day validity
    day = datetime->day;
    switch (datetime->month)
    {
        case 1:
            valid_day = (day >= 1 && day <= 31);
            break;
        case 2:
            // Check for leap year.
            // Year must be divisible by 4.
            if ((datetime->year % 4) == 0)
            {
                // If also divisible by 100, not a leap year
                // unless divisible by 400.
                if ((datetime->year % 100) == 0)
                    is_leap_year = ((datetime->year % 400) == 0);
                else
                    is_leap_year = true;
            }
            valid_day = (day >= 1 && day <= (uint32_t)(is_leap_year ? 29 : 28));
            break;
        case 3:
            valid_day = (day >= 1 && day <= 31);
            break;
        case 4:
            valid_day = (day >= 1 && day <= 30);
            break;
        case 5:
            valid_day = (day >= 1 && day <= 31);
            break;
        case 6:
            valid_day = (day >= 1 && day <= 30);
            break;
        case 7:
            valid_day = (day >= 1 && day <= 31);
            break;
        case 8:
            valid_day = (day >= 1 && day <= 31);
            break;
        case 9:
            valid_day = (day >= 1 && day <= 30);
            break;
        case 10:
            valid_day = (day >= 1 && day <= 31);
            break;
        case 11:
            valid_day = (day >= 1 && day <= 30);
            break;
        case 12:
            valid_day = (day >= 1 && day <= 31);
            break;
        default:
            OE_RAISE(OE_INVALID_UTC_DATE_TIME);
    }

    if (!valid_day)
        OE_RAISE(OE_INVALID_UTC_DATE_TIME);

    // Check hour, minutes, seconds
    if (datetime->hours >= 24 || datetime->minutes >= 60 ||
        datetime->seconds >= 60)
        OE_RAISE(OE_INVALID_UTC_DATE_TIME);

    result = OE_OK;
done:
    return result;
}

OE_INLINE uint8_t oe_num_to_str(uint32_t num, uint8_t digits, char* p)
{
    uint32_t d = 0;
    for (int32_t i = digits - 1; i >= 0; --i)
    {
        d = num % 10;
        num /= 10;
        p[i] = (char)('0' + d);
    }
    return digits;
}

OE_INLINE uint8_t oe_str_to_num(const char* p, uint8_t digits, uint32_t* num)
{
    *num = (uint32_t)(p[0] - '0');
    for (int32_t i = 1; i < digits; ++i)
    {
        *num = *num * 10 + (uint32_t)(p[i] - '0');
    }
    return digits;
}

oe_result_t oe_datetime_to_string(
    const oe_datetime_t* datetime,
    char* str,
    size_t* str_length)
{
    oe_result_t result = OE_FAILURE;
    char* p = str;
    if (datetime == NULL || str_length == NULL)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (str == NULL || *str_length < OE_DATETIME_STR_SIZE)
    {
        *str_length = OE_DATETIME_STR_SIZE;
        OE_RAISE_NO_TRACE(OE_BUFFER_TOO_SMALL);
    }

    OE_CHECK(oe_datetime_is_valid(datetime));

    p += oe_num_to_str(datetime->year, 4, p);
    *p++ = '-';

    p += oe_num_to_str(datetime->month, 2, p);
    *p++ = '-';

    p += oe_num_to_str(datetime->day, 2, p);
    *p++ = 'T';

    p += oe_num_to_str(datetime->hours, 2, p);
    *p++ = ':';

    p += oe_num_to_str(datetime->minutes, 2, p);
    *p++ = ':';

    p += oe_num_to_str(datetime->seconds, 2, p);
    *p++ = 'Z';

    // Null terminator.
    *p++ = 0;
    *str_length = OE_DATETIME_STR_SIZE;
    result = OE_OK;
done:
    return result;
}

oe_result_t oe_datetime_from_string(
    const char* str,
    size_t str_length,
    oe_datetime_t* datetime)
{
    const char* p = str;
    oe_result_t result = OE_FAILURE;
    if (str == NULL || str_length < 20 || datetime == NULL)
        OE_RAISE(OE_INVALID_PARAMETER);

    p += oe_str_to_num(p, 4, &datetime->year);
    if (*p++ != '-')
        OE_RAISE(OE_INVALID_UTC_DATE_TIME);

    p += oe_str_to_num(p, 2, &datetime->month);
    if (*p++ != '-')
        OE_RAISE(OE_INVALID_UTC_DATE_TIME);

    p += oe_str_to_num(p, 2, &datetime->day);
    if (*p++ != 'T')
        OE_RAISE(OE_INVALID_UTC_DATE_TIME);

    p += oe_str_to_num(p, 2, &datetime->hours);
    if (*p++ != ':')
        OE_RAISE(OE_INVALID_UTC_DATE_TIME);

    p += oe_str_to_num(p, 2, &datetime->minutes);
    if (*p++ != ':')
        OE_RAISE(OE_INVALID_UTC_DATE_TIME);

    p += oe_str_to_num(p, 2, &datetime->seconds);

    if (*p++ != 'Z')
        OE_RAISE(OE_INVALID_UTC_DATE_TIME);

    OE_CHECK(oe_datetime_is_valid(datetime));

    result = OE_OK;
done:
    return result;
}

int32_t oe_datetime_compare(
    const oe_datetime_t* date1,
    const oe_datetime_t* date2)
{
    if (date1->year != date2->year)
        return (date1->year < date2->year) ? -1 : 1;

    if (date1->month != date2->month)
        return (date1->month < date2->month) ? -1 : 1;

    if (date1->day != date2->day)
        return (date1->day < date2->day) ? -1 : 1;

    if (date1->hours != date2->hours)
        return (date1->hours < date2->hours) ? -1 : 1;

    if (date1->minutes != date2->minutes)
        return (date1->minutes < date2->minutes) ? -1 : 1;

    if (date1->seconds != date2->seconds)
        return (date1->seconds < date2->seconds) ? -1 : 1;

    return 0;
}

oe_result_t oe_datetime_now(oe_datetime_t* value)
{
    oe_result_t result = OE_UNEXPECTED;
    time_t now;
    struct tm timeinfo;

    if (value == NULL)
        OE_RAISE(OE_INVALID_PARAMETER);

#ifndef OE_BUILD_ENCLAVE
    time(&now);
#else
    now = (time_t)(oe_get_time() / 1000);
#endif
    gmtime_r(&now, &timeinfo);

    value->year = (uint32_t)timeinfo.tm_year + 1900;
    value->month = (uint32_t)timeinfo.tm_mon + 1;
    value->day = (uint32_t)timeinfo.tm_mday;
    value->hours = (uint32_t)timeinfo.tm_hour;
    value->minutes = (uint32_t)timeinfo.tm_min;
    value->seconds = (uint32_t)timeinfo.tm_sec;

    result = OE_OK;
done:

    return result;
}

void oe_datetime_log(const char* msg, const oe_datetime_t* date)
{
    if (oe_get_current_logging_level() >= OE_LOG_LEVEL_VERBOSE)
    {
        char str[OE_DATETIME_STR_SIZE];
        size_t size = sizeof(str);
        oe_datetime_to_string(date, str, &size);
        OE_TRACE_VERBOSE("%s %s\n", msg, str);
    }
}
