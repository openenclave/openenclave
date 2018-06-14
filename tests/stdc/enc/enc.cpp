// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <ctype.h>
#include <endian.h>
#include <errno.h>
#include <inttypes.h>
#include <inttypes.h>
#include <iso646.h>
#include <limits.h>
#include <openenclave/bits/malloc.h>
#include <openenclave/bits/tests.h>
#include <openenclave/enclave.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <wchar.h>
#include <wctype.h>
#include "../args.h"

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

static bool _calledAllocationFailureCallback;

static void _AllocationFailureCallback(
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

    _calledAllocationFailureCallback = true;
}

OE_ECALL void Test(void* args_)
{
    TestArgs* args = (TestArgs*)args_;

    oe_set_allocation_failure_callback(_AllocationFailureCallback);

    strcpy(args->buf1, "AAA");
    strcat(args->buf1, "BBB");
    strcat(args->buf1, "CCC");

    {
        char* s = strdup("strdup");

        if (s && strcmp(s, "strdup") == 0 && strlen(s) == 6)
        {
            if (memcmp(s, "strdup", 6) == 0)
                args->strdupOk = 1;
        }
        else
            args->strdupOk = 0;

        free(s);
    }

    snprintf(args->buf2, sizeof(args->buf2), "%s=%d", "value", 100);

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

    struct timeval tv = {0, 0};
    OE_TEST(gettimeofday(&tv, NULL) == 0);

    struct timespec ts;
    clock_gettime(0, &ts);

    /* Sleep for a second */
    timespec req = {1, 0};
    timespec rem;
    nanosleep(&req, &rem);

    OE_TEST(TestSetjmp() == 999);

    /* Cause malloc() to fail */
    void* p = malloc(1024 * 1024 * 1024);
    OE_TEST(p == NULL);
    OE_TEST(_calledAllocationFailureCallback);

#if 0
    printf("UINT_MIN=%u UINT_MAX=%u\n", 0, UINT_MAX);
    printf("INT_MIN=%d INT_MAX=%d\n", INT_MIN, INT_MAX);
    printf("LONG_MIN=%ld LONG_MAX=%ld\n", LONG_MIN, LONG_MAX);
#endif
}
