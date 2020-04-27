// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

/*
   This file is a clone of ../../../3rdparty/libcxxrt/libcxxrt/test/test.cc
   except that we need the ability to run each of the tests it wraps separately,
   so we redefine the main() method. main() function is moved to corresponding
   test file in tests/libcxxrt/enc/<test_name>.cpp
*/

#include <stdio.h>
#include <stdlib.h>
#if defined(__linux__)
#include <unistd.h>
#endif

static int succeeded;
static int failed;
static bool verbose;

#if defined(__linux__)
#define OE_NEWLINE "\r\n"
#elif defined(_WIN32)
#define OE_NEWLINE "\n"
#endif

void log_test(bool predicate, const char* file, int line, const char* message)
{
    if (predicate)
    {
        printf("Test passed: %d: %s" OE_NEWLINE, line, message);
        succeeded++;
        return;
    }
    failed++;
    printf("Test failed: %d: %s" OE_NEWLINE, line, message);
}

static void log_totals(void)
{
    printf(
        OE_NEWLINE "%d tests, %d passed, %d failed" OE_NEWLINE,
        succeeded + failed,
        succeeded,
        failed);
}
