// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_INTERNAL_DATETIME_H
#define _OE_INTERNAL_DATETIME_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

// ISO 8601 format: YYYY-MM-DDThh:mm:ssZ
#define OE_DATETIME_FORMAT ("YYYY-MM-DDThh:mm:ssZ")

#ifdef _WIN32
#define gmtime_r(now, timeinfo) gmtime_s(timeinfo, now)
#endif

/**
 * Check whether the given issue date is a valid date time.
 */
oe_result_t oe_datetime_is_valid(const oe_datetime_t* issue_date);

/**
 * Convert an datetime to string in OE_DATETIME_FORMAT.
 */
oe_result_t oe_datetime_to_string(
    const oe_datetime_t* date_time,
    char* str,
    size_t* str_length);

/**
 * Convert an string in OE_DATETIME_FORMAT to datetime.
 */
oe_result_t oe_datetime_from_string(
    const char* str,
    size_t str_length,
    oe_datetime_t* issue_date);

/**
 * Compare given datetime values.
 */
int32_t oe_datetime_compare(
    const oe_datetime_t* date1,
    const oe_datetime_t* date2);

/**
 * Return the current system time in GMT time.
 */
oe_result_t oe_datetime_now(oe_datetime_t* value);

/**
 * Log the given datetime.
 */
void oe_datetime_log(const char* msg, const oe_datetime_t* date);

OE_EXTERNC_END

#endif /* _OE_INTERNAL_DATETIME_H */
