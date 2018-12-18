// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/properties.h>
#include <openenclave/enclave.h>

#include "../common/test.h"
#include "safecrt_t.h"

void enc_test_memcpy_s()
{
    test_memcpy_s();
}

void enc_test_memmove_s()
{
    test_memmove_s();
}

void enc_test_strncpy_s()
{
    test_strncpy_s();
}

void enc_test_strncat_s()
{
    test_strncat_s();
}

void enc_test_memset_s()
{
    test_memset_s();
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    1024, /* HeapPageCount */
    1024, /* StackPageCount */
    2);   /* TCSCount */
