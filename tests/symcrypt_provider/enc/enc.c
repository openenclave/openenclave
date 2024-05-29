// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/crypto/init.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/tests.h>
#ifdef USE_ENTROPY_EDL
#include "symcrypt_provider_t.h"
#else
#include "symcrypt_provider_no_entropy_t.h"
#endif

void ecall_test()
{
    OE_TEST(oe_is_symcrypt_provider_available() == 1);
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    1024, /* NumHeapPages */
    1024, /* NumStackPages */
    1);   /* NumTCS */
