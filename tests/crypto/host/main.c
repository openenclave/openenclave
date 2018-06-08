// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <assert.h>
#include <openenclave/bits/cert.h>
#include <openenclave/bits/ec.h>
#include <openenclave/bits/hexdump.h>
#include <openenclave/bits/raise.h>
#include <openenclave/bits/random.h>
#include <openenclave/bits/rsa.h>
#include <openenclave/bits/sha.h>
#include <openenclave/bits/tests.h>
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../ec_tests.h"
#include "../hash.h"
#include "../random_tests.h"
#include "../rsa_tests.h"
#include "../sha_tests.h"

const char* arg0;

int main(int argc, const char* argv[])
{
    arg0 = argv[0];

    /* Run the tests */
    TestEC();
    TestRandom();
    TestRSA();
    TestSHA();

    printf("=== passed all tests (%s)\n", arg0);

    return 0;
}
