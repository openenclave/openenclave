// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#if defined(OE_BUILD_ENCLAVE)
#include <openenclave/enclave.h>
#endif

#include <openenclave/internal/cert.h>
#include <openenclave/internal/crypto/crl.h>
#include <openenclave/internal/hexdump.h>
#include <openenclave/internal/tests.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "readfile.h"
#include "tests.h"
#if defined(_WIN32)
#define timegm _mkgmtime
#endif

#define ACCEPTABLE_ERROR_IN_SECONDS 60

/* _CERT1 loads intermediate.cert.pem
 * _CERT2 loads leaf.cert.pem
 * _CHAIN1 loads leaf.cert.pem & root.cert.pem
 * _CHAIN2 loads intermediate.cert.pem & root.cert.pem
 * _CRL1 loads intermediate.crl.der, which revokes leaf.cert.pem
 * _CRL2 loads root.crl.der, which also revokes leaf.cert.pem
 */

size_t crl_size1, crl_size2;
static char _CERT1[max_cert_size];
static char _CERT2[max_cert_size];
static char _CHAIN1[max_cert_chain_size];
static char _CHAIN2[max_cert_chain_size];
static uint8_t _CRL1[max_cert_size];
static uint8_t _CRL2[max_cert_size];
oe_datetime_t _time;

static void _test_verify(
    const char* cert_pem,
    const char* chain_pem,
    const oe_crl_t* crl[],
    size_t num_crl,
    bool revoked)
{
    oe_cert_t cert;
    oe_cert_chain_t chain;
    oe_result_t r;

    r = oe_cert_read_pem(&cert, cert_pem, strlen(cert_pem) + 1);
    OE_TEST(r == OE_OK);

    r = oe_cert_chain_read_pem(&chain, chain_pem, strlen(chain_pem) + 1);
    OE_TEST(r == OE_OK);

    if (!crl)
        OE_TEST(num_crl == 0);

    if (crl)
        OE_TEST(num_crl > 0);

    r = oe_cert_verify(&cert, &chain, crl, num_crl);

    if (revoked)
    {
        OE_TEST(r == OE_VERIFY_REVOKED);
    }
    else
    {
        OE_TEST(r == OE_OK);
    }

    oe_cert_free(&cert);
    oe_cert_chain_free(&chain);
}

static void _test_verify_with_crl(
    const char* cert_pem,
    const char* chain_pem,
    const uint8_t* crl_der,
    const size_t crl_der_size,
    bool revoked)
{
    printf("=== begin %s()\n", __FUNCTION__);

    oe_crl_t crl;

    OE_TEST(oe_crl_read_der(&crl, crl_der, crl_der_size) == OE_OK);

    const oe_crl_t* crls[] = {&crl};
    _test_verify(cert_pem, chain_pem, crls, 1, revoked);

    OE_TEST(oe_crl_free(&crl) == OE_OK);

    printf("=== passed %s()\n", __FUNCTION__);
}

static void _test_verify_without_crl(
    const char* cert_pem,
    const char* chain_pem)
{
    printf("=== begin %s()\n", __FUNCTION__);
    _test_verify(cert_pem, chain_pem, NULL, 0, false);
    printf("=== passed %s()\n", __FUNCTION__);
}

static bool _year_is_a_leap_year(uint32_t year)
{
    if (year % 4 == 0)
    {
        if (year % 100 == 0)
        {
            if (year % 400 == 0)
            {
                return true;
            }
            else
            {
                return false;
            }
        }
        else
        {
            return true;
        }
    }
    else
    {
        return false;
    }
}

static int _diff_oe_datetime(oe_datetime_t* t1, oe_datetime_t* t2)
{
    struct tm tm1, tm2;

    tm1.tm_sec = (int)t1->seconds;
    tm1.tm_min = (int)t1->minutes;
    tm1.tm_hour = (int)t1->hours;
    tm1.tm_mday = (int)t1->day;
    tm1.tm_mon = (int)t1->month;
    tm1.tm_year = (int)t1->year;
    tm1.tm_isdst = -1;

    tm2.tm_sec = (int)t2->seconds;
    tm2.tm_min = (int)t2->minutes;
    tm2.tm_hour = (int)t2->hours;
    tm2.tm_mday = (int)t2->day;
    tm2.tm_mon = (int)t2->month;
    tm2.tm_year = (int)t2->year;
    tm2.tm_isdst = -1;

    time_t time1 = timegm(&tm1);
    time_t time2 = timegm(&tm2);
    return (int)(time2 - time1);
}

static void _print_oe_datetime(const char* s, const oe_datetime_t* t)
{
    fprintf(
        stderr,
        "[%s] Year=%u, Month=%u, Day=%u, Hour=%u, Minute=%u, Second=%u\n",
        s,
        t->year,
        t->month,
        t->day,
        t->hours,
        t->minutes,
        t->seconds);
}

static void _test_get_dates(void)
{
    printf("=== begin %s()\n", __FUNCTION__);

    oe_crl_t crl;

    OE_TEST(oe_crl_read_der(&crl, _CRL1, crl_size1) == OE_OK);

    oe_datetime_t last;
    oe_datetime_t next;
    OE_TEST(oe_crl_get_update_dates(&crl, &last, &next) == OE_OK);

    _print_oe_datetime("Actual CRL last", &last);
    _print_oe_datetime("Expected CRL last", &_time);

    int diff = _diff_oe_datetime(&last, &_time);
    OE_TEST(abs(diff) < ACCEPTABLE_ERROR_IN_SECONDS);

    oe_datetime_t next_expected;
    next_expected.year = last.year + 1;
    next_expected.month = last.month;
    next_expected.day = last.day;
    next_expected.hours = last.hours;
    next_expected.minutes = last.minutes;
    next_expected.seconds = last.seconds;

    // If a leap day occurs in the next time period, need to adjust
    // expected next date.
    if ((last.month >= 3 && _year_is_a_leap_year(next.year)) ||
        (last.month <= 2 && _year_is_a_leap_year(last.year)))
    {
        next_expected.day -= 1;
        if (next_expected.day == 0)
        {
            // Rollover for month
            next_expected.month -= 1;
            if (next_expected.month == 0)
            {
                // Rollover for year
                next_expected.year -= 1;
                next_expected.month = 12;
            }
            switch (next_expected.month)
            {
                case 2:
                    if (_year_is_a_leap_year(next_expected.year))
                    {
                        next_expected.day = 29;
                    }
                    else
                    {
                        next_expected.day = 28;
                    }
                    break;
                case 4:
                case 6:
                case 9:
                case 11:
                    next_expected.day = 30;
                    break;
                case 1:
                case 3:
                case 5:
                case 7:
                case 8:
                case 10:
                case 12:
                    next_expected.day = 31;
                    break;
            }
        }
    }

    diff = _diff_oe_datetime(&next, &next_expected);

    _print_oe_datetime("Actual CRL next", &next);
    _print_oe_datetime("Expected CRL next", &next_expected);

    OE_TEST(abs(diff) < ACCEPTABLE_ERROR_IN_SECONDS);
    OE_TEST(oe_crl_free(&crl) == OE_OK);

    printf("=== passed %s()\n", __FUNCTION__);
}

static void _test_verify_with_two_crls(
    const char* cert_pem,
    const char* chain_pem,
    const uint8_t* crl1_der,
    const size_t crl1_der_size,
    const uint8_t* crl2_der,
    const size_t crl2_der_size,
    bool revoked)
{
    printf("=== begin %s()\n", __FUNCTION__);

    oe_crl_t crl1;
    oe_crl_t crl2;

    OE_TEST(oe_crl_read_der(&crl1, crl1_der, crl1_der_size) == OE_OK);
    OE_TEST(oe_crl_read_der(&crl2, crl2_der, crl2_der_size) == OE_OK);

    const oe_crl_t* crls[] = {&crl1, &crl2};
    _test_verify(cert_pem, chain_pem, crls, 2, revoked);

    OE_TEST(oe_crl_free(&crl1) == OE_OK);
    OE_TEST(oe_crl_free(&crl2) == OE_OK);

    printf("=== passed %s()\n", __FUNCTION__);
}

void TestCRL(void)
{
    OE_TEST(read_cert("../data/intermediate.cert.pem", _CERT1) == OE_OK);
    OE_TEST(read_cert("../data/leaf.cert.pem", _CERT2) == OE_OK);

    OE_TEST(
        read_chain(
            "../data/leaf.cert.pem",
            "../data/root.cert.pem",
            _CHAIN1,
            OE_COUNTOF(_CHAIN1)) == OE_OK);
    OE_TEST(
        read_chain(
            "../data/intermediate.cert.pem",
            "../data/root.cert.pem",
            _CHAIN2,
            OE_COUNTOF(_CHAIN2)) == OE_OK);

    OE_TEST(
        read_crl("../data/intermediate.crl.der", _CRL1, &crl_size1) == OE_OK);
    OE_TEST(read_crl("../data/root.crl.der", _CRL2, &crl_size2) == OE_OK);

    _test_verify_without_crl(_CERT1, _CHAIN1);
    _test_verify_without_crl(_CERT2, _CHAIN2);

    _test_verify_with_crl(_CERT2, _CHAIN2, _CRL2, crl_size2, true);

    _test_verify_with_two_crls(
        _CERT2, _CHAIN2, _CRL2, crl_size2, _CRL1, crl_size1, true);

    _test_verify_with_two_crls(
        _CERT2, _CHAIN2, _CRL1, crl_size1, _CRL2, crl_size2, true);

    OE_TEST(read_dates("../data/time.txt", &_time) == OE_OK);
    _test_get_dates();
}
