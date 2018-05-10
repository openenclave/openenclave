// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

/* 
   This file is a clone of ../../../3rdparty/libcxxrt/libcxxrt/test/test.cc 
   except that we need the ability to run each of the tests it wraps separately, 
   so we redefine the main() method. main() function is moved to corresponding   
   test file in tests/libcxxrt/enc/<test_name>.cpp
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static int succeeded;
static int failed;
static bool verbose;

void log_test(bool predicate, const char* file, int line, const char* message)
{
    if (predicate)
    {
        printf("Test passed: %s:%d: %s\n", file, line, message);
        succeeded++;
        return;
    }
    failed++;
    printf("Test failed: %s:%d: %s\n", file, line, message);
}

static void log_totals(void)
{
    printf(
        "\n%d tests, %d passed, %d failed\n",
        succeeded + failed,
        succeeded,
        failed);
}
