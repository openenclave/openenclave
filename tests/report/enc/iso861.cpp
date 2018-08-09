// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
#ifdef OE_USE_LIBSGX

#include <openenclave/enclave.h>
#include <openenclave/internal/tests.h>
#include <string.h>
#include "../../../common/quote.h"

void TestPositive(oe_utc_date_time_t dateTime, const char* expected)
{
    char utcString[ISO_861_DATE_LENGTH];
    OE_TEST(convertToISO861(&dateTime, utcString) == OE_OK);
    OE_TEST(strcmp(utcString, expected) == 0);
}

void TestNegative(oe_utc_date_time_t dateTime, oe_result_t result)
{
    char utcString[ISO_861_DATE_LENGTH];
    OE_TEST(convertToISO861(&dateTime, utcString) == result);
}

OE_ECALL void TestIso861Time(void*)
{
    // Single digit fields
    TestPositive(
        oe_utc_date_time_t{2018, 8, 8, 0, 0, 0}, "2018-08-08T00:00:00Z");

    // Double digit day
    TestPositive(
        oe_utc_date_time_t{2018, 8, 18, 0, 0, 0}, "2018-08-18T00:00:00Z");

    // And double digit month
    TestPositive(
        oe_utc_date_time_t{2018, 12, 18, 0, 0, 0}, "2018-12-18T00:00:00Z");

    // Single digit hours
    TestPositive(
        oe_utc_date_time_t{2018, 12, 18, 1, 0, 0}, "2018-12-18T01:00:00Z");

    // And single digit minutes
    TestPositive(
        oe_utc_date_time_t{2018, 12, 18, 1, 1, 0}, "2018-12-18T01:01:00Z");

    // And single digit seconds
    TestPositive(
        oe_utc_date_time_t{2018, 12, 18, 1, 1, 1}, "2018-12-18T01:01:01Z");

    // Double digit seconds
    TestPositive(
        oe_utc_date_time_t{2018, 12, 18, 1, 1, 11}, "2018-12-18T01:01:11Z");

    // And double digit minutes
    TestPositive(
        oe_utc_date_time_t{2018, 12, 18, 1, 13, 11}, "2018-12-18T01:13:11Z");

    // And double digit hours
    TestPositive(
        oe_utc_date_time_t{2018, 12, 18, 21, 13, 11}, "2018-12-18T21:13:11Z");

    // Max valid days for all months except February.
    TestPositive(
        oe_utc_date_time_t{2018, 1, 31, 0, 0, 0}, "2018-01-31T00:00:00Z");
    TestPositive(
        oe_utc_date_time_t{2018, 3, 31, 0, 0, 0}, "2018-03-31T00:00:00Z");
    TestPositive(
        oe_utc_date_time_t{2018, 4, 30, 0, 0, 0}, "2018-04-30T00:00:00Z");
    TestPositive(
        oe_utc_date_time_t{2018, 5, 31, 0, 0, 0}, "2018-05-31T00:00:00Z");
    TestPositive(
        oe_utc_date_time_t{2018, 6, 30, 0, 0, 0}, "2018-06-30T00:00:00Z");
    TestPositive(
        oe_utc_date_time_t{2018, 7, 31, 0, 0, 0}, "2018-07-31T00:00:00Z");
    TestPositive(
        oe_utc_date_time_t{2018, 8, 31, 0, 0, 0}, "2018-08-31T00:00:00Z");
    TestPositive(
        oe_utc_date_time_t{2018, 9, 30, 0, 0, 0}, "2018-09-30T00:00:00Z");
    TestPositive(
        oe_utc_date_time_t{2018, 10, 31, 0, 0, 0}, "2018-10-31T00:00:00Z");
    TestPositive(
        oe_utc_date_time_t{2018, 11, 30, 0, 0, 0}, "2018-11-30T00:00:00Z");
    TestPositive(
        oe_utc_date_time_t{2018, 12, 31, 0, 0, 0}, "2018-12-31T00:00:00Z");

    // February. Non leap year.
    TestPositive(
        oe_utc_date_time_t{2018, 2, 28, 0, 0, 0}, "2018-02-28T00:00:00Z");
    TestNegative(
        oe_utc_date_time_t{2018, 2, 29, 0, 0, 0}, OE_INVALID_UTC_DATE_TIME);

    // February. Leap year.
    TestPositive(
        oe_utc_date_time_t{2004, 2, 29, 0, 0, 0}, "2004-02-29T00:00:00Z");

    // Divisible by 4 and 100 is not a leap year.
    TestPositive(
        oe_utc_date_time_t{2100, 2, 28, 0, 0, 0}, "2100-02-28T00:00:00Z");
    TestNegative(
        oe_utc_date_time_t{2100, 2, 29, 0, 0, 0}, OE_INVALID_UTC_DATE_TIME);

    // Unless divisible by 400.
    TestPositive(
        oe_utc_date_time_t{2000, 2, 29, 0, 0, 0}, "2000-02-29T00:00:00Z");

    oe_host_printf("TestIso861Time passed\n");
}

OE_ECALL void TestIso861TimeNegative(void*)
{
    // Year before unix epoh 1970.
    TestNegative(
        oe_utc_date_time_t{1969, 8, 8, 0, 0, 0}, OE_INVALID_UTC_DATE_TIME);

    // Zero and 13 months
    TestNegative(
        oe_utc_date_time_t{2018, 0, 8, 0, 0, 0}, OE_INVALID_UTC_DATE_TIME);
    TestNegative(
        oe_utc_date_time_t{2018, 0, 13, 0, 0, 0}, OE_INVALID_UTC_DATE_TIME);

    // Invalid hour, minutes, seconds.
    TestNegative(
        oe_utc_date_time_t{2018, 8, 8, 24, 0, 0}, OE_INVALID_UTC_DATE_TIME);
    TestNegative(
        oe_utc_date_time_t{2018, 8, 8, 0, 60, 0}, OE_INVALID_UTC_DATE_TIME);
    TestNegative(
        oe_utc_date_time_t{2018, 8, 8, 0, 0, 60}, OE_INVALID_UTC_DATE_TIME);

    // Invalid days for all months except February.
    TestNegative(
        oe_utc_date_time_t{2018, 1, 32, 0, 0, 0}, OE_INVALID_UTC_DATE_TIME);
    TestNegative(
        oe_utc_date_time_t{2018, 3, 32, 0, 0, 0}, OE_INVALID_UTC_DATE_TIME);
    TestNegative(
        oe_utc_date_time_t{2018, 4, 31, 0, 0, 0}, OE_INVALID_UTC_DATE_TIME);
    TestNegative(
        oe_utc_date_time_t{2018, 5, 32, 0, 0, 0}, OE_INVALID_UTC_DATE_TIME);
    TestNegative(
        oe_utc_date_time_t{2018, 6, 31, 0, 0, 0}, OE_INVALID_UTC_DATE_TIME);
    TestNegative(
        oe_utc_date_time_t{2018, 7, 32, 0, 0, 0}, OE_INVALID_UTC_DATE_TIME);
    TestNegative(
        oe_utc_date_time_t{2018, 8, 32, 0, 0, 0}, OE_INVALID_UTC_DATE_TIME);
    TestNegative(
        oe_utc_date_time_t{2018, 9, 31, 0, 0, 0}, OE_INVALID_UTC_DATE_TIME);
    TestNegative(
        oe_utc_date_time_t{2018, 10, 32, 0, 0, 0}, OE_INVALID_UTC_DATE_TIME);
    TestNegative(
        oe_utc_date_time_t{2018, 11, 31, 0, 0, 0}, OE_INVALID_UTC_DATE_TIME);
    TestNegative(
        oe_utc_date_time_t{2018, 12, 32, 0, 0, 0}, OE_INVALID_UTC_DATE_TIME);

    // Normally Feb has max 28 days.
    TestNegative(
        oe_utc_date_time_t{2018, 2, 29, 0, 0, 0}, OE_INVALID_UTC_DATE_TIME);

    // An year divisible by 4 and 100 is not a leap year.
    TestNegative(
        oe_utc_date_time_t{2100, 2, 29, 0, 0, 0}, OE_INVALID_UTC_DATE_TIME);

    // Unless divisible by 400
    TestNegative(
        oe_utc_date_time_t{2000, 2, 30, 0, 0, 0}, OE_INVALID_UTC_DATE_TIME);

    oe_host_printf("TestIso861TimeNegative passed\n");
}

#endif
