// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <crypto.h>
#include <dl.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/tests.h>

void test_name_conflict(void)
{
    OE_TEST(test_crypto() == 5);
    OE_TEST(test_dl() == 6);
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    1024, /* NumHeapPages */
    1024, /* NumStackPages */
    2);   /* NumTCS */
