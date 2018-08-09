// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_ISSUEDATE_H
#define _OE_ISSUEDATE_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>
#include <openenclave/internal/raise.h>

OE_EXTERNC_BEGIN

// ISO 861 format: YYYY-MM-DDThh:mm:ssZ
#define OE_ISSUE_DATE_FORMAT ("%04d-%02d-%02dT%02d:%02d:%02dZ")

/**
 * oe_issue_date_t structure holds a UTC time value used as argument to
 * oe_verify_report.
 */
typedef struct _oe_issue_date
{
    uint32_t year;
    uint32_t month;
    uint32_t day;
    uint32_t hours;
    uint32_t minutes;
    uint32_t seconds;
} oe_issue_date_t;

OE_CHECK_SIZE(sizeof(oe_issue_date_t), 24);

/**
 * Checked whether the given issue date is a valid date time.
 */
OE_INLINE oe_result_t oe_issue_date_is_valid(const oe_issue_date_t* issue_date)
{
    oe_result_t result = OE_FAILURE;
    bool is_leap_year = false;
    bool valid_day = false;
    uint32_t day = 0;

    if (issue_date == NULL)
        OE_RAISE(OE_INVALID_PARAMETER);

    // Validate the issue_date.
    // Check against unix epoch time (Jan 1, 1970)
    if (issue_date->year < 1970)
        OE_RAISE(OE_INVALID_UTC_DATE_TIME);

    // Check month and day validity
    day = issue_date->day;
    switch (issue_date->month)
    {
        case 1:
            valid_day = (day >= 1 && day <= 31);
            break;
        case 2:
            // Check for leap year.
            // Year must be divisible by 4.
            if ((issue_date->year % 4) == 0)
            {
                // If also divisible by 100, not a leap year 
                // unless divisible by 400.            
                if ((issue_date->year % 100) == 0)
                    is_leap_year = ((issue_date->year % 400) == 0);
                else
                    is_leap_year = true;
            }        
            valid_day = (day >= 1 && day <= (is_leap_year ? 29 : 28));
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

    // Check hour, minutes, seconts
    if (issue_date->hours >= 24 || issue_date->minutes >= 60 ||
        issue_date->seconds >= 60)
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
        p[i] = '0' + d;
    }
    return digits;
}

OE_INLINE uint8_t oe_str_to_num(const char* p, uint8_t digits, uint32_t* num)
{
    *num = p[0] - '0';
    for (int32_t i = 1; i < digits; ++i)
    {
        *num = *num * 10 + (p[i] - '0');
    }
    return digits;
}

/**
 * Convert an issue date to string using ISSUE_DATE_FORMAT.
 */
oe_result_t oe_issue_date_to_string(
    const oe_issue_date_t* issue_date,
    char* str,
    size_t* str_length)
{
    oe_result_t result = OE_FAILURE;
    char* p = str;
    if (issue_date == NULL || str_length == NULL)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (str == NULL || *str_length < 21)
    {
        *str_length = 21;
        OE_RAISE(OE_BUFFER_TOO_SMALL);
    }

    OE_CHECK(oe_issue_date_is_valid(issue_date));

    p += oe_num_to_str(issue_date->year, 4, p);
    *p++ = '-';

    p += oe_num_to_str(issue_date->month, 2, p);
    *p++ = '-';

    p += oe_num_to_str(issue_date->day, 2, p);
    *p++ = 'T';

    p += oe_num_to_str(issue_date->hours, 2, p);
    *p++ = ':';

    p += oe_num_to_str(issue_date->minutes, 2, p);
    *p++ = ':';

    p += oe_num_to_str(issue_date->seconds, 2, p);
    *p++ = 'Z';

    // Null terminator.
    *p++ = 0;
    *str_length = 21;
    result = OE_OK;
done:
    return result;
}

/**
 * Convert an issue date to string using ISSUE_DATE_FORMAT.
 */
oe_result_t oe_issue_date_from_string(
    const char* str,
    size_t str_length,
    oe_issue_date_t* issue_date)
{
    const char* p = str;
    oe_result_t result = OE_FAILURE;
    if (str == NULL || str_length != 21 || issue_date == NULL)
        OE_RAISE(OE_INVALID_PARAMETER);

    p += oe_str_to_num(p, 4, &issue_date->year);
    if (*p++ != '-')
        OE_RAISE(OE_INVALID_UTC_DATE_TIME);

    p += oe_str_to_num(p, 2, &issue_date->month);
    if (*p++ != '-')
        OE_RAISE(OE_INVALID_UTC_DATE_TIME);

    p += oe_str_to_num(p, 2, &issue_date->day);
    if (*p++ != 'T')
        OE_RAISE(OE_INVALID_UTC_DATE_TIME);

    p += oe_str_to_num(p, 2, &issue_date->hours);
    if (*p++ != ':')
        OE_RAISE(OE_INVALID_UTC_DATE_TIME);

    p += oe_str_to_num(p, 2, &issue_date->minutes);
    if (*p++ != ':')
        OE_RAISE(OE_INVALID_UTC_DATE_TIME);

    p += oe_str_to_num(p, 2, &issue_date->seconds);
    if (*p++ != 'Z')
        OE_RAISE(OE_INVALID_UTC_DATE_TIME);

    OE_CHECK(oe_issue_date_is_valid(issue_date));

    result = OE_OK;
done:
    return result;
}

OE_EXTERNC_END

#endif /* _OE_ISSUEDATE_H */
