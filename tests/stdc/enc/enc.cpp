// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <ctype.h>
#include <endian.h>
#include <errno.h>
#include <inttypes.h>
#include <iso646.h>
#include <limits.h>
#include <openenclave/edger8r/enclave.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/malloc.h>
#include <openenclave/internal/tests.h>
#include <openenclave/internal/time.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <wchar.h>
#include <wctype.h>
#include "stdc_t.h"

/* ATTN: implement these! */
#if 0
#include <complex.h>
#include <float.h>
#include <math.h>
#include <time.h>
#endif

void Test_strtol()
{
    long x = strtol("1234", NULL, 10);
    OE_TEST(x == 1234);
}

void Test_strtoll()
{
    long x = strtoll("1234", NULL, 10);
    OE_TEST(x == 1234);
}

void Test_strtoul()
{
    unsigned long x = strtoul("1234", NULL, 10);
    OE_TEST(x == 1234);
}

void Test_strtoull()
{
    unsigned long long x = strtoull("1234", NULL, 10);
    OE_TEST(x == 1234);
}

void Test_strtof()
{
    double x = strtof("0.0", NULL);
    OE_TEST(x == 0);
}

void Test_strtod()
{
    double x = strtod("1.0", NULL);
    OE_TEST(x == 1.0);
}

void Test_strtold()
{
    long double x = strtold("1.0", NULL);
    OE_TEST(x == 1.0);
}

int compare(const void* p1, const void* p2)
{
    return *((int*)p1) - *((int*)p2);
}

void Test_qsort()
{
    int arr[] = {100, 300, 200};
    qsort(arr, OE_COUNTOF(arr), sizeof(int), compare);
    OE_TEST(arr[0] == 100);
    OE_TEST(arr[1] == 200);
    OE_TEST(arr[2] == 300);
}

void Test_bsearch()
{
    int arr[] = {100, 300, 200};
    void* key = &arr[1];
    void* r = bsearch(key, arr, OE_COUNTOF(arr), sizeof(int), compare);
    OE_TEST(r != NULL);
    OE_TEST(r == key);
}

void Test_abs()
{
    OE_TEST(abs(-1) == 1);
    OE_TEST(abs(1) == 1);
    OE_TEST(abs(0) == 0);
}

void Test_labs()
{
    OE_TEST(labs(-1) == 1);
    OE_TEST(labs(1) == 1);
    OE_TEST(labs(0) == 0);
}

void Test_llabs()
{
    OE_TEST(llabs(-1) == 1);
    OE_TEST(llabs(1) == 1);
    OE_TEST(llabs(0) == 0);
}

#if 0
void Test_div()
{
    div_t r = div(5, 3);
    OE_TEST(r.quot == 1);
    OE_TEST(r.rem == 2);
}
#endif

int TestSetjmp()
{
    jmp_buf buf;

    int rc = setjmp(buf);

    if (rc == 999)
        return rc;

    longjmp(buf, 999);
    return 0;
}

void Test_atox()
{
    OE_TEST(atoi("100") == 100);
    OE_TEST(atol("100") == 100L);
    OE_TEST(atoll("100") == 100LL);
    OE_TEST(atof("1.0") == 1.0);
}

static bool _called_allocation_failure_callback;

static void _allocation_failure_callback(
    const char* file,
    size_t line,
    const char* func,
    size_t size)
{
    printf(
        "oe_allocation_failure_callback_t(): %s(%zu): %s: %zu\n",
        file,
        line,
        func,
        size);

    _called_allocation_failure_callback = true;
}

static void _test_time_functions(void)
{
    const uint64_t SEC_TO_USEC = 1000000UL;
    const uint64_t JAN_1_2018 = 1514786400UL * SEC_TO_USEC;
    const uint64_t JAN_1_2050 = 2524629600UL * SEC_TO_USEC;
    uint64_t now;

    /* Test time(): this test will fail if run after Jan 1, 2050 */
    {
        now = static_cast<uint64_t>(time(NULL)) * SEC_TO_USEC;
        OE_TEST(now != 0);
        OE_TEST(now >= JAN_1_2018 && now <= JAN_1_2050);
    }

    /* Test gettimeofday() */
    {
        struct timeval tv = {0, 0};
        OE_TEST(gettimeofday(&tv, NULL) == 0);

        const uint64_t tmp = static_cast<uint64_t>(tv.tv_sec) * SEC_TO_USEC;

        /* Check for accuracy within a second */
        OE_TEST(now >= tmp - SEC_TO_USEC);
        OE_TEST(now <= tmp + SEC_TO_USEC);
    }

    /* Test clock_gettime() */
    {
        struct timespec ts;
        OE_TEST(clock_gettime(0, &ts) == 0);

        uint64_t tmp = static_cast<uint64_t>(ts.tv_sec) * SEC_TO_USEC;

        /* Check for accuracy within a second */
        OE_TEST(tmp >= now - SEC_TO_USEC);
        OE_TEST(tmp <= now + SEC_TO_USEC);
    }

    /* Test nanosleep() */
    {
        const uint64_t SLEEP_SECS = 3;

        uint64_t before = oe_get_time();

        /* Sleep for SLEEP_SECS seconds */
        {
            timespec req = {SLEEP_SECS, 0};
            timespec rem;
            OE_TEST(nanosleep(&req, &rem) == 0);
        }

        uint64_t after = oe_get_time();

        OE_TEST(after > before);
    }
}

int test(char buf1[BUFSIZE], char buf2[BUFSIZE])
{
    int rval = 0;

    oe_set_allocation_failure_callback(_allocation_failure_callback);

    strcpy(buf1, "AAA");
    strcat(buf1, "BBB");
    strcat(buf1, "CCC");

    {
        char* s = strdup("strdup");

        if (s && strcmp(s, "strdup") == 0 && strlen(s) == 6 &&
            memcmp(s, "strdup", 6) == 0)
        {
            rval = 1;
        }

        free(s);
    }

    snprintf(buf2, BUFSIZE, "%s=%d", "value", 100);

    Test_strtol();
    Test_strtoll();
    Test_strtoul();
    Test_strtoull();
    Test_strtof();
    Test_strtod();
    Test_strtold();
    Test_qsort();
    Test_bsearch();
    Test_abs();
    Test_labs();
    Test_llabs();
#if 0
    Test_div();
#endif
    Test_atox();

    _test_time_functions();

    OE_TEST(TestSetjmp() == 999);

    /* Cause malloc() to fail */
    void* p = malloc(1024 * 1024 * 1024);
    OE_TEST(p == NULL);

    OE_TEST(_called_allocation_failure_callback);

    return rval;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    1024, /* NumHeapPages */
    1024, /* NumStackPages */
    2);   /* NumTCS */
