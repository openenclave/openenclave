// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "../edltestutils.h"

#include <errno.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include "all_t.h"

void test_errno_edl_ocalls()
{
    errno = 0;
    OE_TEST(errno == 0);

    OE_TEST(ocall_errno() == OE_OK);
    OE_TEST(errno == 0x12345678);

    printf("=== test_errno_edl_ocalls passed\n");
}
