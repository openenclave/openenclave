// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/crypto/init.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/tests.h>
#include "symcrypt_engine_t.h"

void ecall_test()
{
    OE_TEST(oe_is_symcrypt_engine_available() == 1);
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    1024, /* NumHeapPages */
    1024, /* NumStackPages */
    1);   /* NumTCS */
