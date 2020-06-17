// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/datetime.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <string.h>
#include "../../../common/sgx/quote.h"
#include "tests_t.h"

void TestPositive(const oe_datetime_t& date_time, const char* expected)
{
    char utc_string[21];
    size_t length = sizeof(utc_string);
    OE_TEST(oe_datetime_to_string(&date_time, utc_string, &length) == OE_OK);
    OE_TEST(strcmp(utc_string, expected) == 0);

    oe_datetime_t date_time_round_trip = {0};
    OE_TEST(
        oe_datetime_from_string(utc_string, length, &date_time_round_trip) ==
        OE_OK);
    OE_TEST(memcmp(&date_time, &date_time_round_trip, sizeof(date_time)) == 0);
}

void TestNegative(oe_datetime_t date_time, oe_result_t result)
{
    char utc_string[21];
    size_t length = sizeof(utc_string);
    OE_TEST(oe_datetime_to_string(&date_time, utc_string, &length) == result);
}

void test_iso8601_time()
{
    // Single digit fields
    TestPositive(oe_datetime_t{2018, 8, 8, 0, 0, 0}, "2018-08-08T00:00:00Z");

    // Double digit day
    TestPositive(oe_datetime_t{2018, 8, 18, 0, 0, 0}, "2018-08-18T00:00:00Z");

    // And double digit month
    TestPositive(oe_datetime_t{2018, 12, 18, 0, 0, 0}, "2018-12-18T00:00:00Z");

    // Single digit hours
    TestPositive(oe_datetime_t{2018, 12, 18, 1, 0, 0}, "2018-12-18T01:00:00Z");

    // And single digit minutes
    TestPositive(oe_datetime_t{2018, 12, 18, 1, 1, 0}, "2018-12-18T01:01:00Z");

    // And single digit seconds
    TestPositive(oe_datetime_t{2018, 12, 18, 1, 1, 1}, "2018-12-18T01:01:01Z");

    // Double digit seconds
    TestPositive(oe_datetime_t{2018, 12, 18, 1, 1, 11}, "2018-12-18T01:01:11Z");

    // And double digit minutes
    TestPositive(
        oe_datetime_t{2018, 12, 18, 1, 13, 11}, "2018-12-18T01:13:11Z");

    // And double digit hours
    TestPositive(
        oe_datetime_t{2018, 12, 18, 21, 13, 11}, "2018-12-18T21:13:11Z");

    // Max valid days for all months except February.
    TestPositive(oe_datetime_t{2018, 1, 31, 0, 0, 0}, "2018-01-31T00:00:00Z");
    TestPositive(oe_datetime_t{2018, 3, 31, 0, 0, 0}, "2018-03-31T00:00:00Z");
    TestPositive(oe_datetime_t{2018, 4, 30, 0, 0, 0}, "2018-04-30T00:00:00Z");
    TestPositive(oe_datetime_t{2018, 5, 31, 0, 0, 0}, "2018-05-31T00:00:00Z");
    TestPositive(oe_datetime_t{2018, 6, 30, 0, 0, 0}, "2018-06-30T00:00:00Z");
    TestPositive(oe_datetime_t{2018, 7, 31, 0, 0, 0}, "2018-07-31T00:00:00Z");
    TestPositive(oe_datetime_t{2018, 8, 31, 0, 0, 0}, "2018-08-31T00:00:00Z");
    TestPositive(oe_datetime_t{2018, 9, 30, 0, 0, 0}, "2018-09-30T00:00:00Z");
    TestPositive(oe_datetime_t{2018, 10, 31, 0, 0, 0}, "2018-10-31T00:00:00Z");
    TestPositive(oe_datetime_t{2018, 11, 30, 0, 0, 0}, "2018-11-30T00:00:00Z");
    TestPositive(oe_datetime_t{2018, 12, 31, 0, 0, 0}, "2018-12-31T00:00:00Z");

    // February. Non leap year.
    TestPositive(oe_datetime_t{2018, 2, 28, 0, 0, 0}, "2018-02-28T00:00:00Z");
    TestNegative(oe_datetime_t{2018, 2, 29, 0, 0, 0}, OE_INVALID_UTC_DATE_TIME);

    // February. Leap year.
    TestPositive(oe_datetime_t{2004, 2, 29, 0, 0, 0}, "2004-02-29T00:00:00Z");

    // Divisible by 4 and 100 is not a leap year.
    TestPositive(oe_datetime_t{2100, 2, 28, 0, 0, 0}, "2100-02-28T00:00:00Z");
    TestNegative(oe_datetime_t{2100, 2, 29, 0, 0, 0}, OE_INVALID_UTC_DATE_TIME);

    // Unless divisible by 400.
    TestPositive(oe_datetime_t{2000, 2, 29, 0, 0, 0}, "2000-02-29T00:00:00Z");

    // hours, minutes and seconds are zero based.
    // Maximum possible value of hours, minutes and seconds.
    TestPositive(
        oe_datetime_t{2000, 2, 29, 23, 59, 59}, "2000-02-29T23:59:59Z");

    oe_host_printf("TestIso8601Time passed\n");
}

void test_iso8601_time_negative()
{
    // Year before unix epoch 1970.
    TestNegative(oe_datetime_t{1969, 8, 8, 0, 0, 0}, OE_INVALID_UTC_DATE_TIME);

    // Zero and 13 months
    TestNegative(oe_datetime_t{2018, 0, 8, 0, 0, 0}, OE_INVALID_UTC_DATE_TIME);
    TestNegative(oe_datetime_t{2018, 13, 8, 0, 0, 0}, OE_INVALID_UTC_DATE_TIME);

    // Invalid hour, minutes, seconds.
    TestNegative(oe_datetime_t{2018, 8, 8, 24, 0, 0}, OE_INVALID_UTC_DATE_TIME);
    TestNegative(oe_datetime_t{2018, 8, 8, 0, 60, 0}, OE_INVALID_UTC_DATE_TIME);
    TestNegative(oe_datetime_t{2018, 8, 8, 0, 0, 60}, OE_INVALID_UTC_DATE_TIME);

    // Invalid days for all months except February.
    TestNegative(oe_datetime_t{2018, 1, 32, 0, 0, 0}, OE_INVALID_UTC_DATE_TIME);
    TestNegative(oe_datetime_t{2018, 3, 32, 0, 0, 0}, OE_INVALID_UTC_DATE_TIME);
    TestNegative(oe_datetime_t{2018, 4, 31, 0, 0, 0}, OE_INVALID_UTC_DATE_TIME);
    TestNegative(oe_datetime_t{2018, 5, 32, 0, 0, 0}, OE_INVALID_UTC_DATE_TIME);
    TestNegative(oe_datetime_t{2018, 6, 31, 0, 0, 0}, OE_INVALID_UTC_DATE_TIME);
    TestNegative(oe_datetime_t{2018, 7, 32, 0, 0, 0}, OE_INVALID_UTC_DATE_TIME);
    TestNegative(oe_datetime_t{2018, 8, 32, 0, 0, 0}, OE_INVALID_UTC_DATE_TIME);
    TestNegative(oe_datetime_t{2018, 9, 31, 0, 0, 0}, OE_INVALID_UTC_DATE_TIME);
    TestNegative(
        oe_datetime_t{2018, 10, 32, 0, 0, 0}, OE_INVALID_UTC_DATE_TIME);
    TestNegative(
        oe_datetime_t{2018, 11, 31, 0, 0, 0}, OE_INVALID_UTC_DATE_TIME);
    TestNegative(
        oe_datetime_t{2018, 12, 32, 0, 0, 0}, OE_INVALID_UTC_DATE_TIME);

    // Normally Feb has max 28 days.
    TestNegative(oe_datetime_t{2018, 2, 29, 0, 0, 0}, OE_INVALID_UTC_DATE_TIME);

    // Zero day test.
    TestNegative(oe_datetime_t{2018, 2, 0, 0, 0, 0}, OE_INVALID_UTC_DATE_TIME);

    // A year divisible by 4 and 100 is not a leap year.
    TestNegative(oe_datetime_t{2100, 2, 29, 0, 0, 0}, OE_INVALID_UTC_DATE_TIME);

    // Unless divisible by 400
    TestNegative(oe_datetime_t{2000, 2, 30, 0, 0, 0}, OE_INVALID_UTC_DATE_TIME);

    // Invalid hours, minutes, seconds.
    TestNegative(
        oe_datetime_t{2000, 2, 29, 24, 0, 0}, OE_INVALID_UTC_DATE_TIME);
    TestNegative(
        oe_datetime_t{2000, 2, 29, 0, 60, 0}, OE_INVALID_UTC_DATE_TIME);
    TestNegative(
        oe_datetime_t{2000, 2, 29, 0, 0, 60}, OE_INVALID_UTC_DATE_TIME);

    oe_host_printf("TestIso8601TimeNegative passed\n");
}
